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

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC

scan_severities = {
    "LOW": 3.9,
    "MEDIUM": 6.9,
    "HIGH": 10.0,
}


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        return json.loads(binary_data.decode("utf8"))

    def normalizer(self, issue):
        issue_cwe = str(issue.get("cwe", "")).lower().strip()
        issue_checker = issue.get("checkerName", None)
        issue_display_kind = issue.get("displayIssueKind", None)
        issue_name = issue.get("displayType")
        code = issue.get("cid")
        scan_severity = issue.get("displayImpact")
        severity = scan_severities.get(scan_severity.upper())

        reference_identifiers = []

        if issue_cwe is not None and issue_cwe and issue_cwe != "":
            reference_identifiers.append({"id": issue_cwe, "type": "cwe"})

        key = ""
        key_values = []
        beg = False

        if issue_checker is not None:
            key += issue_checker.lower().strip()
            key_values.append("issue_checker")
            beg = True

        if issue_display_kind is not None:
            if beg:
                key += "//"

            key += issue_display_kind.lower().strip()
            key_values.append("issue_display_kind")

        issue_display_category = issue.get("displayCategory", "")
        issue_display_function = issue.get("functionName", "")
        issue_function_merge_name = issue.get("functionMergeName", "")

        return {
            "issue_name": issue_name,
            "code": code,
            "severity": severity,
            "scan_severity": scan_severity,
            "key": key,
            "key_values": key_values,
            "reference_identifiers": reference_identifiers,
            "vulnerability_details": [
                {
                    "display_category": issue_display_category,
                    "display_function": issue_display_function,
                    "display_file_name": issue["filePathname"],
                    "display_component": issue.get("componentName", ""),
                    "display_issue_kind": issue.get("displayIssueKind", ""),
                    "function_merge_name": issue_function_merge_name,
                    "first_detected": issue.get("firstDetected", ""),
                    "code": code,
                },
            ],
        }
