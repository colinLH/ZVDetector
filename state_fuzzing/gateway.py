import os
import re
import sys
import json
import time
import signal
import asyncio
from typing import Tuple, List

sys.path.append(os.path.dirname(os.getcwd()))

import zigpy_znp
import zigpy.zdo
import zigpy.zcl
import zigpy.device
import zigpy.endpoint
import zigpy.application
import zigpy.exceptions
from zigpy.zcl import foundation, convert_list_schema
import zigpy.types as t
import zigpy.zdo.types as zdo_t
import zigpy_znp.frames
from zigpy_znp.api import ZNP
from zigpy_znp.config import CONFIG_SCHEMA
from zigpy_znp.zigbee.application import ControllerApplication
from zigpy_znp.tools.common import setup_parser, ClosableFileType, validate_backup_json

from util.logger import get_logger
from util.conf import ZIGBEE_DEVICE_MAC_MAP
from util.serial import serialize
from util.utils import find_files_with_prefix, input_with_timeout, get_struct_time
from llm.model import BERT
from network_backup import backup_network
from network_restore import restore_network

import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


# log = get_logger()  # If color log

# python fuzzer.py -c 20 -d 15 -l -o network.json /dev/tty.usbserial-14110
def parse_args(argv, notification):
    parser = setup_parser(notification)
    parser.add_argument(
        "-c",
        "--channels",
        dest="channels",
        type=lambda s: t.Channels.from_channel_list(map(int, s.split(","))),
        default=t.Channels.ALL_CHANNELS,
        help="Channels on which to scan for networks",
    )

    parser.add_argument(
        "-d",
        "--duration",
        dest="duration",
        type=int,
        default=60,
        help="Permit duration",
    )
    parser.add_argument(
        "-l",
        "--load_state",
        action="store_true",
        help="Use state to guide fuzzing",
    )

    parser.add_argument(
        "-r",
        "--reset",
        action="store_true",
        help="Reset the network",
    )

    parser.add_argument(
        "--input", "-i", type=ClosableFileType("r"), required=False, help="Input file"
    )

    parser.add_argument(
        "--output", "-o", type=ClosableFileType("w"), required=True, help="Output file"
    )

    args = parser.parse_args(argv)
    # log.info(args.input)
    if args.reset and args.input is None:
        raise InputTimeoutError("Restore the network but no information!")

    return args


def get_attribute_id(cluster: zigpy.zcl.Cluster, attribute_name: str) -> t.uint16_t:
    if attribute_name not in cluster.attributes_by_name.keys():
        return t.uint16_t(0)
    else:
        return t.uint16_t(cluster.attributes_by_name[attribute_name].id)


def get_attribute_name(cluster: zigpy.zcl.Cluster, attribute_id: int) -> str:
    for attribute_name, attribute_def in cluster.attributes_by_name.items():
        if attribute_def.id == t.uint16_t(attribute_id):
            return attribute_name
    return "Manufacturer-Specific"


class ZHAGateway:
    def __init__(self, args):
        self.name = "snoff usb dongle 3.0"
        self.device_path = args.serial
        self.reset_dongle = args.reset
        self.config = {"channels": args.channels,
                       "duration": args.duration,
                       "device": {"path": args.serial},
                       "output": args.output,
                       "state_guide": args.load_state}

        self.application_controller = ControllerApplication(self.config)
        self.coordinator_ieee = t.EUI64.convert("00:12:4b:00:30:cb:d7:43")
        self.parent_nwk = t.NWK.convert("0000")
        self.max_fuzzing_packet = 10
        self.bert_model = BERT()
        self.name2ieee = {a: b for b, a in ZIGBEE_DEVICE_MAC_MAP.items()}
        self.cluster_db = os.path.join(os.getcwd(), "cluster_db")
        self.state_db = os.path.join(os.getcwd(), "state_db")
        self.attribute_db = os.path.join(os.getcwd(), "attribute_db")
        self.case_db = os.path.join(os.getcwd(), "interesting_case")
        self.general_packets = 0
        self.zcl_packets = 0
        self.total_packets = 0

        if self.reset_dongle:
            self.config["reset"] = True
            self.config["input"] = args.input

    async def initialize(self) -> None:
        await self.application_controller.connect()
        log.info("[INITIALIZE] Starting Zigbee Network")

        await self.application_controller.initialize(auto_form=False)
        log.info("[INITIALIZE] Zigbee Network is Ready !")
        # log.info("[##] Existing Devices: {}".format(self.application_controller.devices))

    async def clean(self) -> None:
        await self.application_controller.disconnect()

    async def reset_nwk(self) -> None:
        with self.config["input"] as f:
            backup = json.load(f)
            validate_backup_json(backup)
            await restore_network(
                radio_path=self.config["device"]["path"],
                backup=backup
            )

    async def get_nwk_info(self) -> None:
        with self.config["output"] as f:
            backup_obj = await backup_network(self.application_controller.znp_ins)
            f.write(json.dumps(backup_obj, indent=4))
        log.info("[INITIALIZE] Zigbee Network Information Recorded!")

    async def send_permit(self) -> None:
        await self.application_controller.permit(self.config["duration"])

    async def energy_scan(self) -> None:
        await self.application_controller.energy_scan(self.config["channels"], self.config["duration"], 10)

    async def add_device(self) -> None:
        log.info("[##] Existing Devices: {}".format(self.application_controller.devices))

        with open("network.json", 'r', encoding='utf-8') as file:
            network_info = json.load(file)

        for device in network_info["devices"]:
            if not (device["ieee_address"] and device["nwk_address"]):
                continue
            ieee = t.EUI64.convert(device["ieee_address"])
            nwk = t.NWK.convert(device["nwk_address"])
            log.info("[+] [IEEE: {}, NWK: {}] Add device to application controller!".format(ieee, nwk))
            self.application_controller.add_device(ieee, nwk)
            log.info("[+] [NWK: {}] Initialize device instance".format(nwk))
        #     await self.application_controller.devices[ieee].schedule_initialize()

    async def get_support_cluster(self, ieee: t.EUI64, endpoint: zigpy.endpoint.Endpoint):
        support_cluster_path = "{}/{}_{}.json".format(self.cluster_db, str(ieee), endpoint.endpoint_id)
        if not os.path.exists(support_cluster_path):
            # log.error("No information are fetched during commissioning phase!")
            return None
        with open(support_cluster_path, "r", encoding='utf-8') as f1:
            support_cluster = json.load(f1)
        return support_cluster

    async def get_support_attribute(self):
        attribute_save_path = os.path.join(self.attribute_db, "support_attribute.json")
        if os.path.exists(attribute_save_path):
            with open(attribute_save_path, "r", encoding='utf-8') as fa:
                support_attribute = json.load(fa)
        else:
            support_attribute = dict()
        return support_attribute

    async def get_interesting_case(self, ieee: t.EUI64, endpoint: zigpy.endpoint.Endpoint):
        interesting_case_path = "{}/{}_{}.json".format(self.case_db, str(ieee), endpoint.endpoint_id)
        if os.path.exists(interesting_case_path):
            with open(interesting_case_path, "r", encoding='utf-8') as f:
                interesting_case = json.load(f)
        else:
            interesting_case = {}
        return interesting_case

    async def find_similar_device(self, device_name: str) -> Tuple[t.EUI64, zigpy.device.Device]:
        """
        Using BERT/LLM to get the most similar device according to the given device name

        :param device_name: IoT Device Name
        :return: The IEEE Address and Zigpy.Device Instance of the most similar device
        """
        device_name = self.bert_model.find_pair(device_name, list(ZIGBEE_DEVICE_MAC_MAP.values()))[0]
        ieee = t.EUI64.convert(self.name2ieee[device_name])
        device = self.application_controller.devices[ieee]
        return ieee, device

    async def request_nd(self, ieee: t.EUI64) -> None:
        """
        Requesting the node descriptor of device

        :param ieee: Device IEEE Address
        :return: None
        """
        device = self.application_controller.devices[ieee]
        log.info("[REQUEST] Requesting Node Descriptor")
        status, _, node_desc = await device.zdo.Node_Desc_req(device.nwk)
        if status == zdo_t.Status.SUCCESS:
            log.info("[RESPONSE] Node Descriptor {}".format(node_desc))

    async def request_sd(self, ieee: t.EUI64) -> None:
        """
        Requesting the simple descriptor of device

        :param ieee: Device IEEE Address
        :return: None
        """
        device = self.application_controller.devices[ieee]
        log.info("[REQUEST] Requesting Active Descriptor")
        status, _, endpoints = await device.zdo.Active_EP_req(device.nwk)
        log.info("Discovered endpoints of [{}]: {}".format(device.nwk, endpoints))
        for endpoint_id in endpoints:
            status, _, sd = await device.zdo.Simple_Desc_req(
                device.nwk, endpoint_id
            )
            log.info("[RESPONSE] Endpoint: {}".format(sd))

    async def read_cluster_attribute(self, ieee: t.EUI64, cluster_name: str, cluster_id: int=None) -> dict:
        """

        :param ieee: Device IEEE Address
        :param cluster_name: The name of certain cluster
        :param cluster_id: If Cluster is Manufacturer-Specific, this field need to provide value
        :return: All attributes values with its type are stored in a dictionary
        """
        device = self.application_controller.devices[ieee]
        # log.info("[+] Reading Attribute Value of Cluster: {}".format(cluster_name))

        success, failure = {}, {}

        if cluster_name == "Unknown" and cluster_id is None:
            log.error("[ERROR] Manufacturer-Specific Cluster Need to Provide Cluster ID!")
            return dict()

        for endpoint in device.non_zdo_endpoints:

            support_cluster = await self.get_support_cluster(ieee, endpoint)
            support_attribute = await self.get_support_attribute()
            cluster_attribute = support_attribute[str(ieee)][str(endpoint.endpoint_id)]
            check_id = False

            if cluster_name not in cluster_attribute.keys():
                continue

            if cluster_name == "Unknown":
                check_id = True
            else:
                if cluster_name in support_cluster["input"].keys():
                    cluster_id = support_cluster["input"][cluster_name]
                elif cluster_name in support_cluster["output"].keys():
                    cluster_id = support_cluster["output"][cluster_name]
                else:
                    cluster_id = None

            if cluster_id is None:
                continue

            all_attributes = cluster_attribute[cluster_name]

            for attribute in all_attributes:
                attr_id = t.uint16_t(attribute["attr_id"])
                attr_name = attribute["attr_name"]
                if check_id and attribute["cluster_id"] != cluster_id:
                    continue

                try:
                    result = await self.send_zcl_general(endpoint, t.ClusterId(cluster_id), 0x00, [attr_id])
                    if not isinstance(result[0], list):
                        failure[attr_name] = result[0]
                    else:
                        for record in result[0]:
                            if record.status == foundation.Status.SUCCESS:
                                try:
                                    value_type_id = record.value.type
                                    value_type = foundation.DATA_TYPES[value_type_id][1]
                                    value = value_type(record.value.value)
                                except KeyError:
                                    value_type_id = record.type
                                    value = record.value.value
                                except ValueError:
                                    value_type_id = record.type
                                    value = record.value.value

                                success[attr_name] = {"type": value_type_id, "value": value}
                                # log.info("[RESPONSE] {} Values: {}".format(record_attribute, value))

                            # UNSUPPORTED_ATTRIBUTE, Write Only, other Status
                            else:
                                failure[attr_name] = record.status
                                # log.info("[RESPONSE] {} Status: {}".format(record_attribute, record.status))

                except asyncio.TimeoutError:
                    log.error("[ERROR] Read Attribute Fail! Cluster: {}({}) Attribute: {}"
                              .format(cluster_name, cluster_id, attr_name))
                    continue
        return success

    async def record_cluster(self, ieee: t.EUI64) -> None:
        """
        Record supported cluster of each device in cluster database

        :param ieee: Device IEEE Address
        :return: None
        """
        jsons = find_files_with_prefix(self.cluster_db, str(ieee))
        if jsons:
            return

        log.info("[COMMISSIONING GET] [{}] Discover Cluster".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))

        device = self.application_controller.devices[ieee]
        for endpoint in device.non_zdo_endpoints:
            cluster_dict = {
                "input": {
                    "Unknown": []
                },
                "output": {
                    "Unknown": []
                }
            }

            support_cluster = await self.get_support_cluster(ieee, endpoint)
            if support_cluster is not None:
                continue

            with open("{}/{}_{}.json".format(self.cluster_db, str(ieee), endpoint.endpoint_id), "w") as f:
                for id, cluster in endpoint.in_clusters.items():
                    if cluster.ep_attribute is not None:
                        cluster_dict["input"][cluster.ep_attribute] = cluster.cluster_id
                    else:
                        cluster_dict["input"]["Unknown"].append(id)

                for id, cluster in endpoint.out_clusters.items():
                    if cluster.ep_attribute is not None:
                        cluster_dict["output"][cluster.ep_attribute] = id
                    else:
                        cluster_dict["output"]["Unknown"].append(id)

                json.dump(cluster_dict, f, indent=4)

        log.info("[COMMISSIONING GET] [{}] Discover Cluster Complete".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))

    async def send_zdo_packet(self, ieee: t.EUI64) -> str:
        """
        Sending ZDO packets including Node & Simple Descriptor Request, Read Attributes of Model Information

        :param ieee: Device IEEE Address
        :return: Status(Success or Fail)
        """
        action = input_with_timeout("Action:\n", 10, "")
        if action == "":
            return "Fail"

        # time2 = time.time()

        if action == "simple":
            # log.info("[{}] Endpoints: {}".format(device.nwk, device.non_zdo_endpoints))
            try:
                # log.info("Sending Simple Descriptor Request")
                await self.request_sd(ieee)
                # log.info("Passed Time{}".format(time2 - time1))
            except asyncio.exceptions.TimeoutError:
                return "Fail"

        if action == "node":
            try:
                # log.info("Sending Node Descriptor Request")
                await self.request_nd(ieee)
                # log.info("Passed Time{}".format(time2 - time1))
            except asyncio.exceptions.TimeoutError:
                return "Fail"

        if action == "model":
            try:
                log.info("[REQUEST] [{}] Requesting Model".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))
                await self.read_cluster_attribute(ieee, "basic")
                log.info("[COMPLETE] [{}] Requesting Model Complete".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))
            except asyncio.exceptions.TimeoutError:
                return "Fail"

        return "Success"

    async def get_state(self, ieee: t.EUI64) -> dict:
        """
        (1) Get current state and record in state_db
        (2) Get support attributes and record in attribute_db
        :param ieee: Device IEEE Address
        :return: Current device state or Fail Status
        """
        device = self.application_controller.devices[ieee]
        device_state, failure = {}, {}

        for endpoint in device.non_zdo_endpoints:

            support_cluster = await self.get_support_cluster(ieee, endpoint)
            support_attribute = await self.get_support_attribute()
            cluster_attribute = support_attribute[str(ieee)][str(endpoint.endpoint_id)]

            device_state[str(endpoint.endpoint_id)] = {}

            for all_clusters in support_cluster.values():
                for cluster_name, cluster_id in all_clusters.items():
                    if cluster_name == "Unknown":
                        for cid in cluster_id:
                            save_cluster_name = "Manufacturer-Specific-Cluster_{}".format(cid)
                            device_state[str(endpoint.endpoint_id)][save_cluster_name] = {}
                    else:
                        device_state[str(endpoint.endpoint_id)][cluster_name] = {}

            for cluster_name, all_attributes in cluster_attribute.items():
                cluster_id = None

                if cluster_name != "Unknown":
                    if cluster_name in support_cluster["input"].keys():
                        cluster_id = support_cluster["input"][cluster_name]
                    else:
                        cluster_id = support_cluster["output"][cluster_name]

                manufacturer_attribute_count = 0

                for attribute in all_attributes:
                    attr_id = t.uint16_t(attribute["attr_id"])
                    attr_name = attribute["attr_name"]

                    if "cluster_id" in attribute.keys():  # 如果是厂商自定义的cluster
                        cluster_id = attribute["cluster_id"]
                        cluster_name = "Manufacturer-Specific-Cluster_{}".format(cluster_id)
                    try:
                        result = await self.send_zcl_general(endpoint, t.ClusterId(cluster_id), 0x00, [attr_id])
                        if not isinstance(result[0], list):
                            failure[attr_name] = result[0]
                        else:
                            for record in result[0]:
                                if record.status == foundation.Status.SUCCESS:
                                    try:
                                        value_type_id = record.value.type
                                        value_type = foundation.DATA_TYPES[value_type_id][1]
                                        value = value_type(record.value.value)
                                    except KeyError:
                                        value_type_id = record.type
                                        value = record.value.value
                                    except ValueError:
                                        value_type_id = record.type
                                        value = record.value.value

                                    if cluster_name.startswith("Manufacturer-Specific"):
                                        device_state[str(endpoint.endpoint_id)][cluster_name][attr_name] = {"type": value_type_id, "value": value,
                                                                                 "id": attr_id}
                                    elif attr_name == "Manufacturer-Specific":
                                        manufacturer_attribute_count += 1
                                        save_name = "Manufacturer-Specific{}".format(manufacturer_attribute_count)
                                        device_state[str(endpoint.endpoint_id)][cluster_name][save_name] = {"type": value_type_id, "value": value,
                                                                                 "id": attr_id}
                                    else:
                                        device_state[str(endpoint.endpoint_id)][cluster_name][attr_name] = {"type": value_type_id, "value": value}
                                    # log.info("[RESPONSE] {} Values: {}".format(record_attribute, value))

                                # UNSUPPORTED_ATTRIBUTE, Write Only, other Status
                                else:
                                    failure[attr_name] = record.status
                                    # log.info("[RESPONSE] {} Status: {}".format(record_attribute, record.status))

                    except asyncio.TimeoutError:
                        log.error("[ERROR] Read Attribute Fail! Cluster: {}({}) Attribute: {}"
                                  .format(cluster_name, cluster_id, attr_name))
                        continue
                    except zigpy.exceptions.ParsingError:
                        log.error("[ERROR] Unable to parse response! Cluster: {}({}) Attribute: {}"
                                 .format(cluster_name, cluster_id, attr_name))

        # log.info("[RECORD] [{}] Recording State".format(str(ieee)))
        with open("{}/{}/{}.json".format(self.state_db, str(ieee), get_struct_time()), "w") as f:
            json.dump(device_state, f, indent=4)

        official_attribute_path = "{}/official_attribute.json".format(self.attribute_db)
        if not os.path.exists(official_attribute_path):
            attribute_data = {}
        else:
            with open(official_attribute_path, "r", encoding='utf-8') as f2:
                attribute_data = json.load(f2)

        with open(official_attribute_path, "w") as f3:
            # 如果还没有记录Attribute
            if str(ieee) not in attribute_data.keys():
                attribute_data[str(ieee)] = {}
                for cname in device_state.keys():
                    attribute_data[str(ieee)][cname] = list(device_state[cname].keys())

            json.dump(attribute_data, f3, indent=4)

        return device_state

    async def set_state(self, ieee: t.EUI64, state: dict):
        device = self.application_controller.devices[ieee]
        for endpoint in device.non_zdo_endpoints:

            support_cluster = await self.get_support_cluster(ieee, endpoint)

            state_endpoint = state[str(endpoint.endpoint_id)]
            for cluster_name, cluster_state in state_endpoint.items():
                # cluster_id = None
                cluster = None
                if cluster_name.startswith("Manufacturer-Specific"):
                    cluster_id = re.search(r'\d+', cluster_name).group()
                    if cluster_id not in support_cluster["input"]["Unknown"] \
                            or cluster_id not in support_cluster["output"]["Unknown"]:
                        continue
                elif cluster_name in support_cluster["input"].keys():
                    cluster_id = support_cluster["input"][cluster_name]
                    cluster = endpoint.get_cluster(cluster_name)
                elif cluster_name in support_cluster["output"].keys():
                    cluster_id = support_cluster["output"][cluster_name]
                    cluster = endpoint.get_cluster_from_id(cluster_id)
                else:
                    continue

                for attribute_name, attribute_value in cluster_state.items():
                    attr_type = t.uint8_t(attribute_value["type"])
                    attr_value = foundation.DATA_TYPES[attribute_value["type"]][1](attribute_value["value"])

                    if attribute_name.startswith("Manufacturer-Specific") or cluster is None:
                        attr_type = t.uint8_t(attribute_value["type"])
                        attr_id = t.uint16_t(attribute_value["id"])
                    else:
                        attribute_def = cluster.find_attribute(attribute_name)
                        attr_id = attribute_def.id  # t.uint16_t

                    payload = [attr_id, attr_type, attr_value]

                    await self.send_zcl_general(endpoint, cluster_id, 0x02, payload)

    async def schedule_state_record(self):
        for ieee, name in ZIGBEE_DEVICE_MAC_MAP.items():
            ieee = t.EUI64.convert(ieee)
            if ieee in self.application_controller.devices.keys():
                log.info("[STATE] [{}] Reading State".format(name))
                state = await self.get_state(ieee)
                if "Status" not in state.keys():
                    log.info("[STATE] [{}] Reading Complete".format(name))

    async def discover_attribute(self, ieee: t.EUI64) -> dict:
        """
        Discover the attributes of each cluster of a device (including all the endpoints)
        :param ieee: Device IEEE Address
        :return: All endpoints with all clusters' attributes
        """
        device = self.application_controller.devices[ieee]
        start_attr_id = 0x0000
        max_attr_id = 0xff

        manufacturer_specific_count = 0
        all_result = {}
        for endpoint in device.non_zdo_endpoints:
            endpoint_id = endpoint.endpoint_id
            all_result[endpoint_id] = {}

            support_cluster = await self.get_support_cluster(ieee, endpoint)
            if support_cluster is None:
                continue

            for cluster_kind in support_cluster.keys():
                for cluster_name, cluster_id in support_cluster[cluster_kind].items():
                    if cluster_name not in all_result[endpoint_id].keys():
                        all_result[endpoint_id][cluster_name] = []
                    if cluster_name == "light_color":
                        start_attr_id = 0x0010

                    if cluster_name == "Unknown":
                        cluster_ids = cluster_id
                        cluster = None
                    else:
                        cluster_ids = [cluster_id]
                        try:
                            cluster = endpoint.get_cluster(cluster_name)
                        except AttributeError:
                            cluster = endpoint.get_cluster_from_id(cluster_id)
                        if cluster is None:
                            continue

                    for cid in cluster_ids:
                        try:

                            payload = b''
                            payload += serialize(start_attr_id, t.uint16_t)
                            payload += serialize(max_attr_id, t.uint8_t)

                            result = await self.request_raw(endpoint, cid, 0x0C,
                                                            frame_type=foundation.FrameType.GLOBAL_COMMAND,
                                                            payload_bytes=payload,
                                                            direction=foundation.Direction.Client_to_Server)
                        except asyncio.exceptions.TimeoutError:
                            log.error("[ERROR] Device: {} Endpoint: {} Cluster {} Discover Fail"
                                      .format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)], endpoint.endpoint_id, cluster_name))
                            continue

                        try:
                            attributes = result.attribute_info
                        except AttributeError:
                            continue

                        for attribute in attributes:
                            record_attr = {"attr_type": attribute.datatype,
                                           "attr_id": attribute.attrid}
                            if cluster is not None:
                                record_attr["attr_name"] = get_attribute_name(cluster, attribute.attrid)
                            else:
                                manufacturer_specific_count += 1
                                record_attr["attr_name"] = "Manufacturer-Specific{}".format(manufacturer_specific_count)
                                record_attr["cluster_id"] = cid
                            all_result[endpoint_id][cluster_name].append(record_attr)

                            # log.info("[RESPONSE] TYPE:{} ATTRID: {}".format(foundation.DATA_TYPES[
                            # attribute.datatype][1], attribute.attrid))
        return all_result

    async def begin_attribute_record(self):
        """
        When Zigbee Network formed and device join, record all supported attributes
        :return: None
        """
        attributes = await self.get_support_attribute()

        for ieee in self.application_controller.devices.keys():

            # 如果为协调器或者已经记录过属性的设备，则不探索
            if ieee == self.coordinator_ieee or str(ieee) in attributes.keys():
                continue

            log.info("[COMMISSIONING GET] [{}] Discover Attribute".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))

            result = await self.discover_attribute(ieee)

            log.info("[COMMISSIONING GET] [{}] Discover Attribute Complete".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))

            attributes[str(ieee)] = result

        with open(os.path.join(self.attribute_db, "support_attribute.json"), "w") as f2:
            json.dump(attributes, f2, indent=4)

    async def send_zcl_general(self, endpoint: zigpy.endpoint.Endpoint, cluster_id: t.uint16_t,
                               command_id: int, *args, flag: bool = False, tsn=None, **kwargs):
        # Only request
        command = foundation.GENERAL_COMMANDS[command_id]

        if command.direction == foundation.Direction.Server_to_Client:
            log.error("This is reply")
            return "Fail"

        request = b''
        for element in list(*args):
            # log.info("[DEBUG] {}".format(type(element)))
            request = request + element.serialize()

        if tsn is None:
            tsn = endpoint.device.get_sequence()

        # log.info("[REQUEST] Sending {}".format(command.name))

        frame_control = foundation.FrameControl(
            frame_type=foundation.FrameType.GLOBAL_COMMAND,
            is_manufacturer_specific=False,
            direction=foundation.Direction.Client_to_Server,
            disable_default_response=False,
            reserved=0b0000
        )

        header = foundation.ZCLHeader(
            frame_control=frame_control,
            manufacturer=None,
            tsn=tsn,
            command_id=command.id
        )

        # log.info("Sending request header: {}".format(header))
        # log.info("Sending request: {}".format(request))

        data = header.serialize() + request
        cluster_id = t.ClusterId(cluster_id)

        result = await endpoint.request(cluster_id, header.tsn, data, expect_reply=True, command_id=command_id)

        if flag:
            self.general_packets = self.general_packets + 1

        return result

    async def request_raw(self, endpoint: zigpy.endpoint.Endpoint, cluster_id: int, command_id: int, frame_type: int,
                          payload_bytes: bytes, direction: int, tsn=None, flag: bool = False):

        cluster_id = t.ClusterId(cluster_id)

        if direction == foundation.Direction.Server_to_Client:
            log.error("[ERROR] Select Reply Function!")
            return

        if tsn is None:
            tsn = endpoint.device.get_sequence()

        frame_control = foundation.FrameControl(
            frame_type=frame_type,
            is_manufacturer_specific=False,
            direction=direction,
            disable_default_response=False,
            reserved=0b0000
        )

        header = foundation.ZCLHeader(
            frame_control=frame_control,
            manufacturer=None,
            tsn=tsn,
            command_id=command_id
        )

        data = header.serialize() + payload_bytes

        result = await endpoint.request(cluster_id, header.tsn, data, expect_reply=True, command_id=command_id)

        if flag:
            self.total_packets += 1

        return result

    async def run(self):
        log.info("******************************[Stage 1] Coordinator Initialize Phase*****************************")
        await self.initialize()
        if self.reset_dongle:
            log.info("[INITIALIZE] Reset the Zigbee Network")
            await self.reset_nwk()

        log.info("[INITIALIZE] Record the Zigbee Network Information")
        await self.get_nwk_info()

        print("\n")
        log.info("*********************************[Stage 2] Commissioning Phase*********************************")

        # time1 = time.time()
        await self.send_permit()

        counter = 0
        try:
            while True:
                await asyncio.sleep(5)

                # 可以定期记录状态，如 3min-5min
                if counter % 10 == 1:
                    # log.info("[DEVICES] {}".format(self.application_controller.devices))

                    # Function 1: Record the supported cluster of each device
                    for ieee in self.application_controller.devices.keys():
                        if ieee == self.coordinator_ieee:
                            continue
                        await self.record_cluster(ieee)

                    # Function 2-1: Record the supported attributes of each cluster
                    await self.begin_attribute_record()

                    # Function 2-2: Record the device state in schedule
                    await self.schedule_state_record()

                # log.info("[##] Existing Devices: {}".format(snoff_dongle.application_controller.devices))

                flag = input_with_timeout("Operation:\n", 7, "")
                if flag == "stop":
                    await self.clean()
                    break

                # Function 3: Allowing Zigbee devices to join
                if flag == "permit":
                    await self.send_permit()

                # Function 4 & 5
                if flag == "zdo" or flag == "cluster":
                    device_name = input_with_timeout("Device:\n", 10, "")
                    if device_name == "":
                        continue

                    # Find similar device using BERT
                    ieee, device = await self.find_similar_device(device_name)

                    if ieee not in self.application_controller.devices.keys() or ieee == self.coordinator_ieee:
                        continue

                    # Function 4: Sending ZDO packets to request device information
                    if flag == "zdo":
                        await self.send_zdo_packet(ieee)

                    # Function 5: Sending general commands to request cluster information
                    else:
                        cluster_name = input_with_timeout("Cluster:\n", 10, "")
                        if cluster_name == "":
                            continue
                        try:
                            log.info("[CLUSTER: {}] Reading Attributes".format(cluster_name))
                            result = await self.read_cluster_attribute(ieee, cluster_name)
                            log.info("[CLUSTER: {}] Reading Attributes Complete".format(cluster_name))
                            log.info("[RESULT] Attributes: {}".format(result))

                        except asyncio.exceptions.TimeoutError:
                            log.error("Can't read cluster: {}".format(cluster_name))

                # Function 6: Acquiring the current state and record in state database
                if flag == "state":
                    device_name = input_with_timeout("Device:\n", 10, "")
                    if device_name == "":
                        continue
                    # Find similar device using BERT
                    ieee, _ = await self.find_similar_device(device_name)

                    if ieee not in self.application_controller.devices.keys() or ieee == self.coordinator_ieee:
                        continue

                    log.info("[STATE] [{}] Reading State".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))
                    state = await self.get_state(ieee)
                    if "Status" not in state.keys():
                        log.info("[OUTPUT] [{}] State: {}".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)], state))

                if flag == "fuzzing":
                    break

                if flag == "crash":

                    while True:
                        device_name = input_with_timeout("Device:\n", 10, "")
                        if device_name == "":
                            continue

                        cluster_name = input_with_timeout("Cluster:\n", 7, "")
                        if cluster_name == "":
                            continue

                        # hex_string = input_with_timeout("Payload1:\n", 7, "")
                        # if hex_string == "":
                        #     continue
                        #
                        # hex_string2 = input_with_timeout("Payload2:\n", 7, "")
                        # if hex_string2 == "":
                        #     continue

                        # 命令行输入\x00\x00\xff\xff
                        # payload2 = bytes(hex_string, "latin1")

                        start_attr_id = [0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009]
                        max_attr_id = 0x30  # 0x30

                        for i in range(10):
                            payload = b''
                            payload += serialize(start_attr_id[i], t.uint16_t)
                            payload += serialize(max_attr_id, t.uint8_t)

                            log.info("[PAYLOAD] {}".format(payload))
                            ieee, device = await self.find_similar_device(device_name)
                            for endpoint in device.non_zdo_endpoints:
                                support_cluster = await self.get_support_cluster(ieee, endpoint)
                                try:
                                    cluster = endpoint.get_cluster(cluster_name)
                                except AttributeError:
                                    if cluster_name in support_cluster["output"].keys():
                                        cluster = endpoint.get_cluster_from_id(support_cluster["output"][cluster_name])
                                    else:
                                        cluster = None

                                if cluster is None:
                                    continue

                                try:
                                    await self.request_raw(endpoint, cluster.cluster_id, 0x0c, foundation.FrameType.GLOBAL_COMMAND,
                                                           payload, foundation.Direction.Client_to_Server)

                                except asyncio.exceptions.TimeoutError:
                                    log.error("[ERROR] Payload:{}".format(payload))
                counter += 1
        except KeyboardInterrupt:
            await self.clean()


if __name__ == "__main__":
    arguments = parse_args(sys.argv[1:], "Preparing the environment")
    snoff_dongle = ZHAGateway(arguments)
    asyncio.run(snoff_dongle.run())
