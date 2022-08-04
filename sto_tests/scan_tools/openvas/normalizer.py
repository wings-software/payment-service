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
from gaussian.utils.helper_funcs import strip_cwe_cve


def get_openvas_severity(scan_threat, scan_severity, cvss):
    if cvss:
        try:
            return float(cvss)
        except ValueError:
            pass
    if scan_severity:
        try:
            return float(scan_severity)
        except ValueError:
            pass
    if scan_threat == "Log":
        return 0
    elif scan_threat == "Low":
        return 3
    elif scan_threat == "Medium":
        return 6
    elif scan_threat == "High":
        return 10
    else:
        return -1


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        json_data = json.loads(binary_data.decode("utf8"))
        report = (
            json_data.get("get_reports_response", {})
            .get("report", {})
            .get("report", {})
        )
        raw_issues = report.get("results", {}).get("result", [])

        if isinstance(raw_issues, list):
            return raw_issues
        else:
            return [raw_issues]

    def normalizer(self, issue):
        if not isinstance(issue, dict):
            return
        scan_threat = issue.get("threat", None)
        scan_severity = issue.get("severity", None)
        nvt_name = issue.get("nvt", {}).get("name", None)
        issue_description = issue.get("description")
        cvss = issue.get("nvt", {}).get("cvss_base", None)
        port = issue.get("port", None)
        identifiers = []
        if nvt_name == "Services":
            key = f"{nvt_name}//{issue_description}//{port}"
            key_values = ["nvt_name", "issue_description", "port"]
        else:
            key = f"{nvt_name}//{port}"
            key_values = ["nvt_name", "port"]
        cve_str = strip_cwe_cve(issue.get("nvt", {}).get("cve", None))

        tags = issue.get("nvt", {}).get("tags", None)
        cvss_vectors = re.findall(r"(?<=cvss_base_vector=).*?(?=\|)", tags)
        cvss_vector = None
        if cvss_vectors:
            cvss_vector = cvss_vectors[0]
        if cve_str.lower() != "nocve":
            identifiers = [{"type": "cve", "id": x.strip()} for x in cve_str.split(",")]
        target = issue.get("host", {}).get("#text", None)
        return {
            "issue_name": issue.get("name"),
            "issue_description": issue_description,
            "issue_type": issue.get("nvt", {}).get("type", None),
            "reference_identifiers": identifiers,
            "port": port,
            "target": target,
            "author": issue.get("owner", {}).get("name", None),
            "confidence": issue.get("qod", {}).get("value", None),
            "scan_severity": scan_threat,
            "severity": get_openvas_severity(scan_threat, scan_severity, cvss),
            "cvss": cvss,
            "cvss_vector": cvss_vector,
            "key": key,
            "key_values": key_values,
            "nvt_name": nvt_name,
        }
