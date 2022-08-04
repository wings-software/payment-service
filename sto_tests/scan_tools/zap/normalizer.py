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
import re

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.issue_refinement.refinement.product_info import ScanTypeInfo
from gaussian.utils.helper_funcs import get_severity_value, strip_cwe_cve
from gaussian.utils.text_scrapers import scrape_reference_identifier


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        data = json.loads(binary_data.decode("utf-8"))
        # handle manual uploads
        if "site" in data:
            rebuild_data = []
            site = data.get("site", [])
            for json_obj in site:
                alerts = json_obj.get("alerts", None)
                for alert in alerts:
                    rebuild_data.append(alert)
            data = rebuild_data
        return data

    def normalizer(self, issue):
        link = re.sub(r"\<\/p\>\<p\>", ",", issue.get("reference", "").strip())
        link = re.sub("<[^<]+?>", "", link)

        scan_severity = ""
        if "risk" in issue:
            severity, scan_severity = None, issue.get("risk")
        elif "riskdesc" in issue:
            severity, scan_severity = None, issue.get("riskdesc")

        converted_scan_severity = re.sub(r"\s(.*)$", "", scan_severity)
        if converted_scan_severity.lower() in [
            "informational",
            "low",
            "medium",
            "high",
        ]:
            severity = get_severity_value(converted_scan_severity)
        else:
            return

        issue_name = issue.get("name")
        pluginId = None
        key_values = []
        if "pluginId" in issue:
            pluginId = issue.get("pluginId")
            key = pluginId
            key_values = ["plugin_id"]
        elif "pluginid" in issue:
            pluginId = issue.get("pluginid")
            key_values = ["plugin_id"]
            key = pluginId
        else:
            raise Exception("invalid missing plugin id to create key")
        cweid = issue.get("cweid")
        if cweid:
            key += f"//{cweid}"
            key_values.append("cwe_id")
        wascid = issue.get("wascid")
        if wascid:
            key += f"//{wascid}"
            key_values.append("was_cid")

        source_id = issue.get("sourceid", None)
        other = ""
        if "other" in issue:
            other = issue.get("other")
        elif "otherinfo" in issue:
            other = issue.get("otherinfo")

        message_id = issue.get("messageid", None)
        url = issue.get("url", None)
        zap_alert = issue.get("alert", None)
        attack = issue.get("attack", None)
        param = issue.get("param", None)
        method = issue.get("method", None)

        description = ""
        if "description" in issue:
            description = issue.get("description")
        elif "desc" in issue:
            description = issue.get("desc")

        reference_identifiers = [
            {"type": "cwe", "id": strip_cwe_cve(issue.get("cweid", ""))},
        ]
        new_identifiers = scrape_reference_identifier(other.replace("\n", ""))
        reference_identifiers.extend(
            [x for x in new_identifiers if x not in reference_identifiers],
        )

        return {
            "issue_name": issue_name,
            "issue_description": re.sub("<[^<]+?>", "", description.strip()),
            "reference_identifiers": reference_identifiers,
            "confidence": issue.get("confidence"),
            "scan_type": ScanTypeInfo.DAST,
            "key": key,
            "severity": severity,
            "scan_severity": scan_severity,
            "vulnerability_details": issue.get("evidence", None),
            "remediation_steps": re.sub("<[^<]+?>", "", issue.get("solution", "")),
            "source_id": source_id,
            "other": re.sub("<[^<]+?>", "", other),
            "message_id": message_id,
            "zap_alert": zap_alert,
            "attack": attack,
            "link": link,
            "url": url,
            "param": param,
            "method": method,
            "instances": issue.get("instances"),
            "key_values": key_values,
            "plugin_id": pluginId,
            "cwe_id": cweid,
            "was_cid": wascid,
        }
