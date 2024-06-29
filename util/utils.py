import os
import sys
import typing
import signal
import datetime
from typing import List
import base64
import json


class InputTimeoutError(Exception):
    pass


def timeout_handler(signum, frame):
    raise InputTimeoutError


def input_with_timeout(prompt, timeout, default):
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)

    try:
        user_input = input(prompt)
        signal.alarm(0)
        return user_input
    except InputTimeoutError:
        # log.info("[->] Continue Listening [<-]")
        return default


def find_subdirectories(root_dir: str, target_name: str) -> str:
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for dirname in dirnames:
            if dirname == target_name:
                return os.path.join(dirpath, dirname)
    return "No target directory found!"


def get_struct_time():
    current_time = datetime.datetime.now()

    formatted_time_str = current_time.strftime("%Y%m%d_%H:%M:%S")

    return formatted_time_str


def find_files_with_name(root_dir: str, target_name: str) -> str:
    for filename in os.listdir(root_dir):
        filepath = os.path.join(root_dir, filename)
        if os.path.isfile(filepath) and filename == target_name:
            return filepath

    return "No target file found!"


def find_files_with_prefix(directory: str, prefix: str):
    matching_files = []
    for filename in os.listdir(directory):
        if filename.startswith(prefix):
            full_path = os.path.join(directory, filename)
            if os.path.isfile(full_path):
                matching_files.append(full_path)

    return matching_files


def process_csv(csv_name: str, feature_list: List[str]):
    data = pd.read_csv(csv_name)
    traffic = data.values[:, 0]
    new_csv = pd.DataFrame(columns=feature_list)
    for index in range(data.shape[0]):
        line = traffic[index]
        values = line.split("$")
        print(values)
        new_csv.loc[new_csv.shape[0]] = values
    new_csv.to_csv(csv_name)


def packet_serialization(features):
    base_string = "("
    for index, feature in enumerate(features):
        base_string += str(feature)
        if index != len(features) - 1:
            base_string += ","
    base_string += ")"
    return base_string


def get_latest_file(directory: str) -> str:
    current_time = datetime.datetime.now()

    latest_file = None
    min_time_diff = None

    for filename in os.listdir(directory):
        if filename.endswith('.json'):
            try:
                timestamp_str = filename.rstrip('.json')
                file_time = datetime.datetime.strptime(timestamp_str, '%Y%m%d_%H:%M:%S')

                time_diff = abs((current_time - file_time).total_seconds())

                if min_time_diff is None or time_diff < min_time_diff:
                    min_time_diff = time_diff
                    latest_file = filename
            except ValueError:
                continue

    return latest_file


def get_all_combinations(lst: list):
    if not lst:
        return [[]]
    first_element = lst[0]
    rest_combinations = get_all_combinations(lst[1:])
    result_combinations = []

    if isinstance(first_element, list):
        for item in first_element:
            for combination in rest_combinations:
                result_combinations.append([item] + combination)
    else:
        for combination in rest_combinations:
            result_combinations.append([first_element] + combination)

    return result_combinations


def match_dict_item(dict1: dict, dict2: dict, return_item) -> list:
    if return_item not in dict1.keys():
        return list()

    for name, value in dict2.items():
        if name not in dict1.keys():
            return list()
        if dict1[name] != value:
            return list()

    return dict1[return_item]


if __name__ == "__main__":
    input_list = [1, [1, 2, 3], 3, [4, 5]]
    combinations = get_all_combinations(input_list)
    for combo in combinations:
        print(combo)


