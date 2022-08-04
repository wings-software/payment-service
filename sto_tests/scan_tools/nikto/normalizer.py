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

import json

import xmltodict

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC


class Refiner(RefinerABC):
    def __init__(self):
        self.issue_type = ""

    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        raw_data = binary_data.decode("UTF-8").strip()

        try:
            pre_data = json.dumps(xmltodict.parse(raw_data))
        except Exception:
            config.logger.warn(f"Scan output is malformed\n{str(raw_data)}")
            return []

        jsn_data = json.loads(pre_data)

        # COMP-1222 - Nikto 2.1.6 removes the parent level 'niktoscans' element from results
        if "niktoscans" in jsn_data:
            scans = jsn_data.get("niktoscans", None)
        elif "niktoscan" in jsn_data:
            scans = jsn_data
        else:
            return []

        self.issue_type = "Web scan"

        nikto_scan_results = scans.get("niktoscan", [])
        if not isinstance(nikto_scan_results, list):
            nikto_scan_results = [nikto_scan_results]

        for scan in nikto_scan_results:
            scan_details = scan.get("scandetails", {})

            target_port = scan_details.get("@targetport", None)
            host_header = scan_details.get("@hostheader", None)
            site_ip = scan_details.get("@siteip", None)
            site_name = scan_details.get("@sitename", None)
            target_banner = scan_details.get("@targetbanner", None)
            target_hostname = scan_details.get("@targethostname", None)
            target_ip = scan_details.get("@targetip", None)

            scan_items = scan_details.get("item", [])
            if not isinstance(scan_items, list):
                scan_items = [scan_items]

            for item in scan_items:
                item["@targetport"] = target_port
                item["@hostheader"] = host_header
                item["@siteip"] = site_ip
                item["@sitename"] = site_name
                item["@targetbanner"] = target_banner
                item["@targethostname"] = target_hostname
                item["@targetip"] = target_ip

        return scan_items

    def normalizer(self, issue):
        method = issue.get("@method", None)
        nikto_id = issue.get("@id", None)
        osvdbid = issue.get("@osvdbid", None)
        osvdb_link = issue.get("@osvdblink", None)
        ip_link = issue.get("iplink", None)
        name_link = issue.get("namelink", None)
        uri = issue.get("uri", None)
        target_port = issue.get("@targetport", None)
        host_header = issue.get("@hostheader", None)
        site_ip = issue.get("@siteip", None)
        site_name = issue.get("@sitename", None)
        target_banner = issue.get("@targetbanner", None)
        target_hostname = issue.get("@targethostname", None)
        target_ip = issue.get("@targetip", None)
        issue_description = issue.get("description", None)

        formatted_description = f"""
        Target Host: {target_hostname}
        Target Port: {target_port}
        Target Banner: {target_banner}
        Target IP: {target_ip}
        Site IP: {site_ip}
        Site Name: {site_name}
        Scan IP Link: {ip_link}
        Scan Name Link: {name_link}
        Scan URI: {uri}
        Method: {method}
        Host Header: {host_header}
        Description: {issue_description}
        OSDVDB: OSDVB-{osvdbid}"""

        severity = 10 if int(osvdbid) > 0 else 6

        key = f"{nikto_id}//{target_port}"
        key_values = ["nikto_id", "port"]

        return {
            "issue_name": issue_description,
            "issue_description": formatted_description,
            "issue_type": self.issue_type,
            "severity": severity,
            "port": target_port,
            "target": target_hostname,
            "ip": target_ip,
            "host": target_hostname,
            "link": osvdb_link,
            "code": osvdbid,
            "key": key,
            "key_values": key_values,
            "nikto_id": nikto_id,
        }
