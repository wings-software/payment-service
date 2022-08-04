#
#  ZeroNorth Gauss Issue Normalization Service
#
#  Copyright (C) 2015-2020 ZeroNorth, Inc. All Rights Reserved.
#
#  All information, in plain text or obfuscated form, contained herein
#  is, and remains the property of ZeroNorth, Inc. and its suppliers, if any.
#  The intellectual and technical concepts contained
#  herein are proprietary to ZeroNorth, Inc. and its suppliers
#  and may be covered by U.S. and Foreign Patents,
#  patents in process, and are protected by trade secret or copyright law.
#
#  Dissemination of this information or reproduction of this material
#  is strictly forbidden unless prior written permission is obtained
#  from ZeroNorth, Inc. (support@zeronorth.io)
#
#  https://www.zeronorth.io
#

"""
If debug lines are not showing up add 'level=logging.DEBUG' to logging in source/config/__init__.py
    & make sure to import logging!
"""

import glob
import json
import logging
import os
import uuid
from shutil import rmtree
from zipfile import ZipFile, is_zipfile

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.utils.helper_funcs import get_by_key, match_first


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        issues = []  # the eventual issue list

        json_data = find_unpack_zip(logging, binary_data)
        if isinstance(json_data, tuple):
            # fail with a reasonable message
            _, message = json_data
            raise Exception(message)

        logging.debug(" json object successfully created")
        logging.debug(f"{'--'} REPORT {'--'*5}")
        logging.debug(f"KEYS [root].keys: {json_data.keys()}")
        # pull relevent info
        account_id = get_by_key(json_data, "account_id")
        provider_code = get_by_key(json_data, "provider_code")
        provider_name = get_by_key(json_data, "provider_name")
        get_by_key(json_data, "result_format")

        logging.debug(f"{'--'} LAST_RUN {'--'*5}")
        last_run = get_by_key(json_data, "last_run", silent=True)
        if last_run:
            logging.debug(f"KEYS [last_run]: {last_run.keys()}")
            # pull relevent info
            last_run_time = get_by_key(last_run, "time")
            last_run_version = get_by_key(last_run, "version")
            last_run_summary = get_by_key(last_run, "summary", silent=True)
            logging.debug(f"{'--'} SUMMARY {'--'*5}")
            logging.debug(f"KEYS [last_run_summary]: {last_run_summary.keys()}")
            for el in last_run_summary:
                get_by_key(last_run_summary, el)
            logging.debug(f"{'--'} ------- {'--'*5}")

        logging.debug(f"{'--'} METADATA {'--'*5}")
        metadata = get_by_key(json_data, "metadata", silent=True)
        if metadata:
            logging.debug(f"KEYS [metadata]: {metadata.keys()}")

        logging.debug(f"{'--'} SERVICE_GROUP {'--'*5}")
        service_groups = get_by_key(
            json_data,
            "service_groups",
            default={},
            silent=True,
        )
        if service_groups:
            logging.debug(f"KEYS [service_groups]: [{service_groups.keys()}]")

            tmp_json = get_by_key(
                service_groups,
                "compute",
                default={},
                silent=True,
            )
            tmp_json = get_by_key(
                tmp_json,
                "summaries",
                default={},
                silent=True,
            )
            tmp_json = get_by_key(
                tmp_json,
                "external_attack_surface",
                default={},
                silent=True,
            )
            service_groups_compute = tmp_json
            logging.debug(
                f"COUNT KEYS [compute][external_attack_surface]: found [{len(service_groups_compute.keys())}]",
            )

            tmp_json = get_by_key(
                service_groups,
                "database",
                default={},
                silent=True,
            )
            tmp_json = get_by_key(
                tmp_json,
                "summaries",
                default={},
                silent=True,
            )
            tmp_json = get_by_key(
                tmp_json,
                "external_attack_surface",
                default={},
                silent=True,
            )
            service_groups_database = tmp_json
            logging.debug(
                f"COUNT KEYS [database][external_attack_surface]: [{len(service_groups_database.keys())}]",
            )

        logging.debug(f"{'--'} SG_MAP {'--'*5}")
        sg_map = get_by_key(json_data, "sg_map", aggregate=True)

        logging.debug(f"{'--'} SUBNET_MAP {'--'*5}")
        subnet_map = get_by_key(json_data, "subnet_map", aggregate=True)

        logging.debug(f"{'--'} SERVICE_LIST {'--'*5}")
        get_by_key(json_data, "service_list", aggregate=True)

        logging.debug(f"{'--'} SERVICES {'--'*5}")
        services = get_by_key(json_data, "services", aggregate=True)
        if services:
            logging.debug(f"KEYS [services]: [{services.keys()}]")
            for service in services:
                logging.debug(f"{'--'} {service} {'--'*5}")
                findings = get_by_key(
                    services[service],
                    "findings",
                    aggregate=True,
                )

                for issue in findings:
                    logging.debug(f"{'--'} {issue} {'--'*5}")
                    data = get_by_key(findings, issue, silent=True)
                    logging.debug(f" KEYS [{issue}]: found [{data.keys()}]")
                    checked_items = get_by_key(data, "checked_items")
                    flagged_items = get_by_key(data, "flagged_items")
                    items = get_by_key(data, "items", aggregate=True)

                    logging.debug(f"\t {items[0:3]}...")
                    logging.debug(
                        f" ACTION building issues for [{len(items)}] vulns..."
                    )

                    dashboard_name = get_by_key(data, "dashboard_name")
                    display_path = get_by_key(data, "display_path")
                    id_suffix = get_by_key(data, "id_suffix")
                    level = get_by_key(data, "level")
                    path = get_by_key(data, "path")
                    description = get_by_key(data, "description")
                    rationale = get_by_key(data, "rationale")
                    service = get_by_key(data, "service")
                    # remap levels
                    if level:
                        severity_code = get_normalized_severity(level)
                        severity = get_severity(severity_code)
                    # build new_issues
                    if items and len(items) > 0:
                        for item in items:
                            keypath = item.split(".")
                            new_issue = {
                                "key": issue,
                                "key_values": ["issue"],
                                "issue": issue,
                                "item": item,
                                "issue_name": f"{service}: {description}",
                                "level": level,
                                "issue_description": rationale,
                                "vulnerability_details": description,
                                "scan_severity": severity_code,
                                "severity_code": severity_code,
                                "severity": severity,
                                "dashboard_name": dashboard_name,
                                "display_path": display_path,
                                "id_suffix": id_suffix,
                                "path": path,
                                "service": service,
                                "account_id": account_id,
                                "provider_code": provider_code,
                                "provider_name": provider_name,
                                "last_run_time": last_run_time,
                                "last_run_version": last_run_version,
                                "checked_items": checked_items,
                                "flagged_items": flagged_items,
                            }
                            sgm_el = match_first(sg_map, item)
                            if sgm_el:
                                new_issue["sg_map"] = sgm_el
                            sbm_el = match_first(subnet_map, item)
                            if sbm_el:
                                new_issue["subnet_map"] = sbm_el
                            sgc_el = match_first(service_groups_compute, item)
                            if sgc_el:
                                new_issue["service_groups_compute"] = sgc_el
                            sgd_el = match_first(service_groups_database, item)
                            if sgd_el:
                                new_issue["service_groups_database"] = sgc_el
                            # navigate to the data
                            layer = services
                            for layer_key in keypath:
                                current_layer = get_by_key(
                                    layer,
                                    layer_key,
                                    silent=True,
                                )
                                layer = current_layer
                            # make sure the exit layer is a dict
                            if type(layer) is dict:
                                # get Tags

                                Tags = match_first(layer, "Tags")
                                if Tags:
                                    if "Tags" not in new_issue:
                                        new_issue["tags"] = []
                                    for tag in layer["Tags"]:
                                        if "Key" in tag and "Value" in tag:
                                            new_issue["tags"].append(
                                                f"{tag['Key']}:{tag['Value']}",
                                            )
                                # append additional data
                                for key in layer:
                                    if key.lower() not in new_issue:
                                        new_issue[key.lower()] = layer[key]
                            else:
                                if layer and layer_key:
                                    new_issue["special_value"] = (layer_key, layer)
                            issues.append(new_issue)

        return {"issues": issues, "extra_data": {}}

    def normalizer(self, issue):
        return issue


def find_unpack_zip(logging, binary_data):
    uuid4 = str(uuid.uuid4())
    unique_path = os.path.join("/tmp/", uuid4)
    unique_zip = f"{unique_path}.zip"
    # write minio bytes to zip bytes
    logging.debug("grabing file from minio")
    if type(binary_data) is bytes:
        with open(unique_zip, "wb") as f:
            f.write(binary_data)
        f.close()
    # extract zip to make readable
    logging.debug("unpacking zip")
    if is_zipfile(unique_zip):
        with ZipFile(unique_zip, "r") as zipObj:
            zipObj.extractall(unique_path)
        # find scoutsuite_results_*.js file
        logging.debug("finding the reports file")
        reports_file = glob.glob(
            f"{unique_path}/**/scoutsuite_results_*.js", recursive=True
        )
        if len(reports_file) == 1:
            reports_file = reports_file[0]
        elif len(reports_file) == 0:
            logging.error("no scoutsuite_results_*.js files found")
            return ("ERROR", "no scoutsuite_results_*.js files found")
        elif len(reports_file) > 1:
            logging.error("multiple scoutsuite_results_*.js files found")
            return ("ERROR", "multiple scoutsuite_results_*.js files found")
        logging.debug("finding the reports data in the file")
        if type(reports_file) == str and os.path.exists(reports_file):
            try:
                with open(reports_file) as f:
                    read_data = f.read()
            except OSError:
                return ("ERROR", "possibly running into machine memory limitations")
    else:
        if os.path.exists(unique_zip):
            try:
                with open(unique_zip) as f:
                    read_data = f.read()
            except OSError:
                return ("ERROR", "possibly running into machine memory limitations")
    # unpacking the results
    start_json_index = read_data.find("{")
    if start_json_index > -1:
        read_data = read_data[start_json_index:]
    else:
        logging.error("finding the reports data")
        return ("ERROR", "couldn't find the report data")
    # load the json data
    logging.debug("load in the json")
    json_data = None
    try:
        json_data = json.loads(read_data)
    except Exception as err:
        logging.error("failed to load json")
        logging.error(err)
        return ("ERROR", "invalid json data found")
    # clean up temp file
    if os.path.exists(unique_zip):
        os.remove(unique_zip)
    if os.path.exists(unique_path):
        rmtree(unique_path)
    # return json_data
    if json_data:
        return json_data
    return ("ERROR", "unexpected error loading the json data")


def get_normalized_severity(level):
    if level.lower() == "warning":
        return "LOW"
    elif level.lower() == "danger":
        return "CRITICAL"
    else:
        return -1


def get_severity(level):
    if level == "INFORMATION":
        return 0
    elif level == "LOW":
        return 3
    elif level == "MEDIUM":
        return 6
    elif level == "HIGH":
        return 8
    elif level == "CRITICAL":
        return 10
    else:
        return -1
