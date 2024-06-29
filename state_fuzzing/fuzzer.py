import os
import re
import sys
import copy
import json
import time
import base64
import signal
import typing
import logging
import asyncio

sys.path.append(os.path.dirname(os.getcwd()))

import zigpy.device
from zigpy.zcl import foundation
import zigpy.endpoint
import zigpy.types as t

from util.logger import get_logger
from util.serial import serialize, ZIGBEE_SIGNED_INT_TYPE, ZIGBEE_UNSIGNED_INT_TYPE, ZIGBEE_ENUM_TYPE, \
    ZIGBEE_BITMAP_TYPE, ZIGBEE_DATA_TYPE, ZIGBEE_STR_TYPE, ZIGBEE_INTEGER_TYPE

from util.utils import get_latest_file, input_with_timeout, get_all_combinations, match_dict_item
from util.conf import ZIGBEE_DEVICE_MAC_MAP
from gateway import ZHAGateway, parse_args

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

ZIGBEE_STR_MAX_LENGTH = {
    t.LVBytes: 255,
    t.CharacterString: 255,
    t.LongOctetString: 65535,
    t.LongCharacterString: 65535
}

STATUS = {status.value: status.name for status in foundation.Status}


class Mutator:

    @classmethod
    async def mutate_value(cls, types: typing.Any) -> list:
        """
        According to different types, generate some mutate values
        :param types: zigbee type
        :return: mutate value list
        """
        mutate_value = []
        if types in ZIGBEE_SIGNED_INT_TYPE or types in ZIGBEE_UNSIGNED_INT_TYPE or types in ZIGBEE_ENUM_TYPE \
                or types in ZIGBEE_BITMAP_TYPE:
            bits = types.get_bit()
            max_value = types.max_value
            min_value = types.min_value
            mutate_value.append(int((min_valuzie + max_value) / 2))
            # mutate_value.append(max_value)
            # mutate_value.append(min_value)
            mutate_value.append(max_value + 1)
            mutate_value.append(min_value - 1)
            mutate_value.append(-max_value + 1)
            mutate_value.append(-max_value)
            mutate_value.append(-max_value - 1)
            mutate_value.append(pow(2, bits * 2))
            mutate_value.append(-pow(2, bits * 2))

        if types in ZIGBEE_STR_TYPE:
            max_length = ZIGBEE_STR_MAX_LENGTH[types]
            mutate_value.append("Normal")
            mutate_value.append("")
            mutate_value.append("f" * max_length)
            mutate_value.append("f" * (max_length + 1))
            mutate_value.append("f" * (max_length + 2))

        return mutate_value

    @classmethod
    async def mutate_type(cls, types: typing.Any):
        """

        :param types: 给定数据类型
        :return: 返回针对该类型变异的datatype列表
        """
        mutate_value = []
        mutate_type_name = []
        if types in ZIGBEE_INTEGER_TYPE:
            mutate_value = [foundation.DATA_TYPES.pytype_to_datatype_id(a) for a in ZIGBEE_INTEGER_TYPE if a != types]
            mutate_type_name = [str(a) for a in ZIGBEE_INTEGER_TYPE if a != types]

        if types in ZIGBEE_STR_TYPE:
            mutate_value = [foundation.DATA_TYPES.pytype_to_datatype_id(a) for a in ZIGBEE_STR_TYPE if a != types]
            mutate_type_name = [str(a) for a in ZIGBEE_INTEGER_TYPE if a != types]

        # 正常值和其他变异字段组合
        mutate_value.insert(0, foundation.DATA_TYPES.pytype_to_datatype_id(types))
        mutate_type_name.insert(0, str(types))

        return mutate_value, mutate_type_name

    @classmethod
    async def mutate_payload(cls, payload_component: list, fuzz_prompt: list):
        """
        :param payload_component: Payload composition elements to be mutated
        :param fuzz_prompt: Denote which function to be used to mutate value
        :return: fuzz result
        """
        all_values = []
        fuzzed_payload = []
        mutated_list = []  # Record the mutate value

        # [(value, type: int, to_fuzz: Bool)]
        for index, component in enumerate(payload_component):
            if component[2]:
                mutate_value = await fuzz_prompt[index](component[1])
                all_values.append(mutate_value)
                mutated_list.append(mutate_value)
            else:
                all_values.append(component[0])
                mutated_list.append(None)

        combinations = get_all_combinations(all_values)

        for combo in combinations:
            payload_bytes = b''
            for index, value in enumerate(combo):
                payload_bytes += serialize(value, payload_component[index][1])
            fuzzed_payload.append(payload_bytes)
        return fuzzed_payload, combinations, mutated_list


class Fuzzer:
    def __init__(self, config):
        self.gateway = ZHAGateway(config)
        self.state_guided = args.load_state
        self.max_fuzzing_packet = 1000000
        self.max_iter_packet = 30000
        self.fuzz_info_db = os.path.join(os.getcwd(), "fuzz_detail")

    async def calculate_correlation(self, state, packet) -> dict:
        pass

    async def feed_watchdog(self, ieee: t.EUI64, flag: str, next_state: dict = None):
        if flag == "SET":
            if next_state is None:
                log.error("Can't set empty state!")
                return "Fail"
            await self.gateway.set_state(ieee, next_state)
            return "Success"
        elif flag == "GET":
            state = await self.gateway.get_state(ieee)
            return state
        else:
            log.error("{} not supported!".format(flag))
            raise KeyError

    async def state_feed(self, ieee: t.EUI64):
        device = self.gateway.application_controller.devices[ieee]

        log.info("[State] [{}] Feeding the state to watchdog. Operation: [GET] ".format(device.nwk))
        state = await self.feed_watchdog(ieee, "GET")

        log.info("[State] Calculating next state ··· ")
        next_state = await self.calculate_correlation(state, packet)

        log.info("[State] [{}] Feeding the state to watchdog. Operation: [SET]".format(device.nwk))
        await self.feed_watchdog(ieee, "SET", next_state)

    async def read_attribute_fuzz(self, ieee: t.EUI64):
        device = self.gateway.application_controller.devices[ieee]
        attrid_type = t.uint16_t
        attrid_range = range(45651, attrid_type.max_value + 1)

        log.info("[BRUTE] Fuzzing {}".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))
        for endpoint in device.non_zdo_endpoints:

            support_cluster = await self.gateway.get_support_cluster(ieee, endpoint)
            interesting_case = await self.gateway.get_interesting_case(ieee, endpoint)

            if support_cluster is None:
                continue

            all_cluster_id = []
            for cluster_name, cluster_id in support_cluster["input"].items():
                if cluster_name == "Unknown":
                    all_cluster_id.extend(cluster_id)
                else:
                    all_cluster_id.append(cluster_id)

            for cid in all_cluster_id:
                interesting_attrid = []
                for attrid in attrid_range:
                    log.info("[BRUTE] CID: {} ATTRID: {}".format(cid, attrid))
                    payload = serialize(attrid, attrid_type)
                    try:
                        result = await self.gateway.request_raw(endpoint, cid, 0x00,
                                                                frame_type=foundation.FrameType.GLOBAL_COMMAND,
                                                                payload_bytes=payload,
                                                                direction=foundation.Direction.Client_to_Server,
                                                                flag=True)
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

                                log.info("[RESPONSE] {} Values: {} Type:{}".format(attrid, value, value_type_id))

                            else:
                                log.info("[RESPONSE] {} Status: {}".format(attrid, record.status))

                    except asyncio.TimeoutError:
                        log.error("[Error] Can't read attribute: {} ! ".format(attrid))
                        interesting_attrid.append(attrid)
                        continue
                    except AttributeError:
                        log.error("[Error] No Status in record! {}")
                        interesting_attrid.append(attrid)
                        continue

                if interesting_attrid:
                    if cid not in interesting_case.keys():
                        interesting_case[cid] = {}
                    interesting_case[cid][0x00] = interesting_attrid

            with open("{}/{}_{}.json".format(self.gateway.case_db, str(ieee), endpoint.endpoint_id), "w") as f:
                json.dump(interesting_case, f, indent=4)

    async def write_attribute_fuzz(self, ieee: t.EUI64, fuzz_type: bool=True):
        fuzz_info_path = "{}/fuzzable.json".format(self.fuzz_info_db)

        if os.path.exists(fuzz_info_path):
            with open(fuzz_info_path, "r") as f:
                all_writable_attr = json.load(f)
        else:
            all_writable_attr = {}

        if "writable" not in all_writable_attr.keys():
            all_writable_attr["writable"] = {}

        if str(ieee) not in all_writable_attr["writable"].keys():
            all_writable_attr["writable"][str(ieee)] = []

        saved_dict = copy.deepcopy(all_writable_attr)
        saved_dict["writable"][str(ieee)] = []

        device = self.gateway.application_controller.devices[ieee]

        for endpoint in device.non_zdo_endpoints:

            support_cluster = await self.gateway.get_support_cluster(ieee, endpoint)
            interesting_case = await self.gateway.get_interesting_case(ieee, endpoint)
            support_attribute = await self.gateway.get_support_attribute()

            cluster_attributes = support_attribute[str(ieee)][str(endpoint.endpoint_id)]

            for cluster_name, cluster_value in cluster_attributes.items():
                interesting_payload = []
                interesting_bytes = []

                if cluster_name == "Unknown":
                    cluster_id = None
                elif cluster_name in support_cluster["input"].keys():
                    cluster_id = support_cluster["input"][cluster_name]
                elif cluster_name in support_cluster["output"].keys():
                    cluster_id = support_cluster["output"][cluster_name]
                else:
                    continue

                for attribute in cluster_value:
                    if cluster_name == "Unknown":
                        cluster_id = attribute["cluster_id"]

                    attribute_name = attribute["attr_name"]
                    attribute_id = attribute["attr_id"]
                    attribute_type_id = attribute["attr_type"]
                    attribute_type = foundation.DATA_TYPES[attribute_type_id][1]

                    payload_components = [(attribute_id, t.uint16_t, False), (attribute_type_id, t.uint8_t, fuzz_type),
                                          (0, attribute_type, True)]

                    fuzz_prompt = [Mutator.mutate_value, Mutator.mutate_type, Mutator.mutate_value]

                    all_fuzz_payload, all_fuzz_combination, mutate_list = await Mutator.mutate_payload(
                        payload_components, fuzz_prompt)

                    saved_mutate_value = []
                    saved_mutate_type = []

                    save_info = {"endpoint_id": endpoint.endpoint_id,
                                 "cluster_id": cluster_id,
                                 "cluster_name": cluster_name,
                                 "attribute_id": attribute_id,
                                 "attribute_name": attribute_name,
                                 "attribute_type_id": attribute_type_id,
                                 "attribute_type_name": str(attribute_type)}

                    for fuzz_attr in all_writable_attr["writable"][str(ieee)]:
                        saved_mutate_value = match_dict_item(fuzz_attr, save_info, "mutate_value")
                        saved_mutate_type = match_dict_item(fuzz_attr, save_info, "mutate_type")
                        if not saved_mutate_value:
                            continue
                        break

                    # Whether to fuzz attribute data type?
                    if fuzz_type:
                        save_info["mutate_type"] = list(set(saved_mutate_type) | set(mutate_list[1]))
                    save_info["mutate_value"] = list(set(saved_mutate_value) | set(mutate_list[2]))

                    fuzz_result = []

                    for index, fuzz_payload in enumerate(all_fuzz_payload):
                        if_read_only = False
                        try:
                            log.info("[FUZZ] CID: {} ATTR: {} ATTR TYPE:{} Mutate Value: {}"
                                     .format(cluster_id, all_fuzz_combination[index][0],
                                             all_fuzz_combination[index][1], all_fuzz_combination[index][2]))
                            result = await self.gateway.request_raw(endpoint, cluster_id, 0x02,
                                                                    foundation.FrameType.GLOBAL_COMMAND,
                                                                    payload_bytes=fuzz_payload,
                                                                    direction=foundation.Direction.Client_to_Server,
                                                                    flag=True)
                            if not result:
                                fuzz_result.append("None")
                                continue
                            try:
                                for record in result[0]:
                                    log.info("[RESPONSE] Status: {}".format(record.status))
                                    if record.status in STATUS.keys():
                                        fuzz_result.append(STATUS[record.status])
                                    else:
                                        fuzz_result.append("OTHER")
                                    if record.status == foundation.Status.READ_ONLY:
                                        if_read_only = True
                            except TypeError:
                                log.info("[RESPONSE] Status: {}".format(result.status))
                                if result.status in STATUS.keys():
                                    fuzz_result.append(STATUS[result.status])
                                else:
                                    fuzz_result.append("OTHER")
                                if result.status == foundation.Status.READ_ONLY:
                                    if_read_only = True

                        except asyncio.TimeoutError:
                            interesting_payload.append(all_fuzz_combination[index])
                            interesting_bytes.append(''.join(f'\\x{byte:02x}' for byte in fuzz_payload))

                        # 如果只允许读，则不再fuzz
                        if if_read_only:
                            break

                        # 测试设备是否仍能打开
                        result_on = await self.turn_on_off(ieee, "on")

                        # 如果不能打开，将device enabled位置为1
                        if result_on == "Fail":
                            interesting_payload.append(all_fuzz_combination[index])
                            interesting_bytes.append(''.join(f'\\x{byte:02x}' for byte in fuzz_payload))
                            await self.write_attributes_begin(endpoint.endpoint_id, ieee, cluster_id, 18, 16, 1)

                    if not fuzz_type:
                        save_info["fuzz_value_result"] = fuzz_result
                    else:
                        save_info["fuzz_result"] = fuzz_result
                    saved_dict["writable"][str(ieee)].append(save_info)

                if interesting_payload:
                    if cluster_id not in interesting_case.keys():
                        interesting_case[cluster_id] = {}
                    if 0x02 not in interesting_case[cluster_id].keys():
                        interesting_case[cluster_id][0x02] = {}

                    interesting_case[cluster_id][0x02]["payload"] = interesting_payload
                    interesting_case[cluster_id][0x02]["payload_bytes"] = interesting_bytes

            with open(interesting_case_path, "w") as f:
                json.dump(interesting_case, f, indent=4)

        with open("{}/fuzzable.json".format(self.fuzz_info_db), "w") as f:
            json.dump(saved_dict, f, indent=4)

    async def configure_report_fuzz(self, ieee: t.EUI64):
        """
        Configure_Reporting = 0x06
        :param ieee:
        :return:
        """
        device = self.gateway.application_controller.devices[ieee]
        for endpoint in device.non_zdo_endpoints:
            pass
        pass

    async def read_configuration_fuzz(self, ieee: t.EUI64):
        pass

    async def discover_command_fuzz(self, ieee: t.EUI64):
        """
        Discover_Commands_Received = 0x11
        Discover_Commands_Generated = 0x13
        :param ieee:
        :return:
        """
        pass

    async def discover_attribute_fuzz(self, ieee: t.EUI64):
        """
        Fuzzing Discover_Attributes = 0x0C
        Discover_Attribute_Extended = 0x15
        :param ieee:
        :return:
        """
        pass

    async def fuzzing(self, ieee: t.EUI64):
        fuzz_count = 0
        while fuzz_count < self.max_fuzzing_packet:
            fuzz_count += 1

            if not self.state_guided:
                await self.brute_force()

            # Step 1: Using the last packet and current state to get the next fuzzing state
            await self.state_feed(ieee)
            # Step 1: Calculate the
            log.info("[+] Sending the mutated packet {} for [{}]".format(fuzz_count, nwk))
            # self.mutation(nwk ,ieee)
            await asyncio.sleep(10)

    async def set_recent_state(self, ieee: t.EUI64):
        state_dict = os.path.join(self.gateway.state_db, str(ieee))
        state_file = os.path.join(state_dict, get_latest_file(state_dict))

        with open(state_file, "r", encoding='utf-8') as f:
            state = json.load(f)

        log.info("[STATE] [{}] Setting State".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))
        await self.feed_watchdog(ieee, "SET", state)
        log.info("[STATE] [{}] Setting Complete".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)]))

    async def turn_on_off(self, ieee: t.EUI64, command: str):
        """
        Turn on/off the device if device has the onoff Cluster
        :param command: On / Off
        :param ieee:
        :return:
        """
        command_id = 0x00 if command.lower() == "off" else 0x01

        device = self.gateway.application_controller.devices[ieee]
        for endpoint in device.non_zdo_endpoints:
            support_cluster_path = "{}/{}_{}.json".format(self.gateway.cluster_db,
                                                          str(ieee), endpoint.endpoint_id)
            if not os.path.exists(support_cluster_path):
                print(support_cluster_path)
                continue

            with open(support_cluster_path, "r", encoding='utf-8') as f:
                support_cluster = json.load(f)
                all_cluster_id = support_cluster["input"].values()
                if 0x0006 not in all_cluster_id:
                    # log.error("Device Endpoint{} doesn't have OnOff Cluster".format(endpoint))
                    return

                log.info("[CLUSTER_CMD] {} {}".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)], command))

                try:
                    result = await self.gateway.request_raw(endpoint, 0x0006, command_id,
                                                            frame_type=foundation.FrameType.CLUSTER_COMMAND,
                                                            payload_bytes=b'',
                                                            direction=foundation.Direction.Client_to_Server)
                    log.info("[CLUSTER_CMD] {}".format(result))
                    return "Success"
                except asyncio.exceptions.TimeoutError:
                    log.error("[CLUSTER_CMD] {} {} Failed!".format(ZIGBEE_DEVICE_MAC_MAP[str(ieee)], command))
                    return "Fail"

    async def write_attributes_begin(self, endpoint_id: int, ieee: t.EUI64, cluster_id: int, attr_id: int,
                                     attr_type: int, value):
        device = self.gateway.application_controller.devices[ieee]
        attr_type_spec = foundation.DATA_TYPES[attr_type][1]
        payload_bytes = b''

        if type(value) == str:
            if attr_type_spec not in ZIGBEE_STR_TYPE:
                log.error("[ERROR] Data Type and Value Not Matched!")
        if type(value) == int:
            if attr_type_spec not in ZIGBEE_INTEGER_TYPE:
                log.error("[ERROR] Data Type and Value Not Matched!")

        payload_bytes += serialize(attr_id, t.uint16_t)
        payload_bytes += serialize(attr_type, t.uint8_t)
        payload_bytes += serialize(value, attr_type_spec)

        for endpoint in device.non_zdo_endpoints:
            if endpoint.endpoint_id != endpoint_id:
                continue
            result = await self.gateway.request_raw(endpoint, cluster_id, 0x02, foundation.FrameType.GLOBAL_COMMAND,
                                                    payload_bytes=payload_bytes,
                                                    direction=foundation.Direction.Client_to_Server)
            for record in result[0]:
                log.info("[RESPONSE] Status: {}".format(record.status))

    async def run(self):
        # Initialize gateway and start the zigbee network
        await self.gateway.run()
        log.info(
            "*********************************[Stage 3] Fuzzing Phase*********************************")

        while True:
            flag = input_with_timeout("Operation:\n", 7, "")

            ieee = None
            if flag != "":
                device_name = input_with_timeout("Device:\n", 10, "")
                if device_name == "":
                    continue
                ieee, device = await self.gateway.find_similar_device(device_name)
                if ieee not in self.gateway.application_controller.devices.keys() or ieee == self.gateway.coordinator_ieee:
                    continue

            if flag == "set":
                await self.set_recent_state(ieee)

            if flag == "on" or flag == "off":
                await self.turn_on_off(ieee, flag)

            if flag == "read_fuzz":
                await self.read_attribute_fuzz(ieee)

            if flag == "write_fuzz":
                await self.write_attribute_fuzz(ieee, fuzz_type=False)

            if flag == "write":
                cluster_name = input_with_timeout("Cluster:\n", 10, "")
                if cluster_name == "":
                    continue

                attr_name = input_with_timeout("Attr Name:\n", 10, "")
                if attr_name == "":
                    continue

                attr_value = input_with_timeout("Attr Value:\n", 10, "")
                if attr_value == "":
                    continue

                try:
                    attr_value = int(attr_value)
                except ValueError:
                    pass

                attribute_save_path = os.path.join(self.gateway.attribute_db, "support_attribute.json")
                if not os.path.exists(attribute_save_path):
                    log.error("[ERROR] Support Attribute Json Not Found")

                with open(attribute_save_path, "r") as f:
                    all_attr = json.load(f)

                for endpoint_id in all_attr[str(ieee)].keys():
                    cluster_save_path = os.path.join(self.gateway.cluster_db,
                                                     "{}_{}.json".format(str(ieee), endpoint_id))
                    with open(cluster_save_path, "r") as f2:
                        all_clusters = json.load(f2)

                    all_cluster = all_attr[str(ieee)][endpoint_id].keys()
                    if cluster_name not in all_cluster:
                        continue
                    cluster_attr = all_attr[str(ieee)][endpoint_id][cluster_name]

                    cluster_id = all_clusters["input"][cluster_name]

                    for attr in cluster_attr:
                        if attr["attr_name"] == attr_name:
                            attr_id = attr["attr_id"]
                            attr_type = attr["attr_type"]
                            log.info("Writing {} at {}".format(attr_name, attr_value))
                            await self.write_attributes_begin(int(endpoint_id), ieee, cluster_id, attr_id, attr_type,
                                                              attr_value)


if __name__ == "__main__":
    args = parse_args(sys.argv[1:], "Preparing the environment")
    fuzzer = Fuzzer(args)
    asyncio.run(fuzzer.run())