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

from collections import OrderedDict

import xmltodict

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.utils.helper_funcs import replace_hosts


class Refiner(RefinerABC):
    def __init__(self):
        self.multiple_addresses = True

    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        nmap_issues = []
        target_name = policy_data["targetName"]
        try:
            data = remove_special_symbols(xmltodict.parse(binary_data.decode("utf-8")))

            host_data = data.get("nmaprun", {}).get("host")

            if host_data is None:
                return [get_host_down_issue(data)]

            if not isinstance(host_data, list):
                host_data = [host_data]
                self.multiple_addresses = False

            for host in host_data:
                host_address_list = host.get("address", [])
                if not isinstance(host_address_list, list):
                    host_address_list = [host_address_list]

                self.host_address = ", ".join(
                    [
                        f"{replace_hosts(x.get('addr', None), target_name)} ({x.get('addrtype', None)})"
                        for x in host_address_list
                    ],
                )

                ports_data = host.get("ports", {}).get("port", None)

                if isinstance(ports_data, dict) or isinstance(ports_data, OrderedDict):
                    nmap_issues.extend([ports_data])
                elif isinstance(ports_data, list):
                    nmap_issues.extend(ports_data)
                else:
                    host_status = host.get("status", {})
                    host_state = host_status.get("state", "unknown")
                    state_reason = host_status.get("reason", "unknown")

                    if host.get("hostnames", None) is not None:
                        hostname_data = host.get("hostnames", {}).get("hostname", {})
                        if not isinstance(hostname_data, list):
                            hostname_data = [hostname_data]
                        hostname = ", ".join([x.get("name", "") for x in hostname_data])
                    else:
                        hostname = self.host_address

                    hostname_suffix = "" if hostname is None else f" [{hostname}]"

                    description = f"Host {self.host_address} is {host_state}. Reason {state_reason}."
                    issue_name = (
                        f"Host {self.host_address}{hostname_suffix} is {host_state}"
                    )

                    nmap_issues.append(
                        {
                            "issue_name": issue_name,
                            "issue_description": description,
                            "issue_type": issue_name,
                            "project": self.host_address,
                            "host": self.host_address,
                            "state": host_state,
                            "severity": 0,
                        }
                    )
        except Exception as ex:
            config.logger.error(ex)
            raise

        return nmap_issues

    def normalizer(self, issue):
        vulnerability_details = []
        port = issue.get("portid", None)
        protocol = issue.get("protocol", None)

        name = issue.get("service", {}).get("name", None)
        product = issue.get("service", {}).get("product", None)

        state = issue.get("state", {}).get("state", None)
        reason = issue.get("state", {}).get("reason", None)

        severity = 0

        if self.multiple_addresses:
            issue_name = f"Port {self.host_address}:{port} {protocol} ({state})"
            key = self.host_address + ":" + port + ":" + protocol + ":" + state
            key_values = ["host", "port", "protocol", "state"]
        else:
            issue_name = f"Port {port} {protocol} ({state})"
            key = f"{port}//{protocol}//{state}"
            key_values = ["port", "protocol", "state"]

        issue_description = f"Port: {self.host_address}:{port} {protocol}; State: {state}; Service: {name}; Reason: {reason}; Product: {product}"
        issue_type = f"{state} port"

        scripts = issue.get("script")
        if scripts is None:
            return {
                "key": key,
                "key_values": key_values,
                "issue_name": issue_name,
                "issue_description": issue_description,
                "issue_type": "inventory",
                "project": self.host_address,
                "severity": severity,
                "port": port,
                "host": self.host_address,
                "protocol": protocol,
                "state": state,
            }

        if isinstance(scripts, dict):
            scripts = [scripts]

        for entry in scripts:
            output = entry.get("output", "")
            end_exclude = "Extra information:"
            start_exclude = "Check results:"

            if start_exclude in output:
                start = output.find(start_exclude)
                begining = output
                if start > 0:
                    begining = output[:start]

                end = output.find(end_exclude)
                ending = ""
                if end > 0:
                    ending = output[end:]
                output = begining + ending
            entry_id = entry.get("id")
            if "NOT VULNERABLE" in output:
                continue
            elif "Couldn't find any" in output:
                continue
            elif "ERROR: Script execution failed" in output:
                continue
            elif "VULNERABLE" in output:
                severity = max(10, severity)
                issue_description = f"{issue_description} - {entry_id} : {output}"
            else:
                severity = max(1, severity)

            vulnerability_details.append(f"{entry_id} : {output}")

        return {
            "key": key,
            "key_values": key_values,
            "issue_name": issue_name,
            "issue_description": issue_description,
            "issue_type": issue_type,
            "vulnerability_details": vulnerability_details,
            "project": self.host_address,
            "severity": severity,
            "port": port,
            "host": self.host_address,
            "protocol": protocol,
            "state": state,
        }


def remove_special_symbols(source):
    if isinstance(source, list):
        return [remove_special_symbols(y) for y in source]
    elif isinstance(source, dict):
        for key in list(source.keys()):
            if key[0] == "@":
                source[key[1:]] = remove_special_symbols(source[key])
                del source[key]
            else:
                source[key] = remove_special_symbols(source[key])
        return source
    else:
        return source


def get_host_down_issue(issue):
    runstats = issue.get("nmaprun", {}).get("runstats", {})
    runstats_hosts = runstats.get("hosts", {})

    down = runstats_hosts.get("down")
    if down == "0":
        raise Exception("Unknown scan results for nmap, unable to refine.")

    issue_description = runstats.get("finished", {}).get("summary")
    up = runstats_hosts.get("up")

    if up == "0":
        issue_name = "0 Hosts Up"
    else:
        issue_name = f"{up} Hosts Up; {down} Hosts Down"

    return {
        "issue_name": issue_name,
        "issue_description": issue_description,
        "issue_type": "Host Down",
        "severity": 1,
        "key": issue_name,
        "key_values": ["issue_name"],
    }
