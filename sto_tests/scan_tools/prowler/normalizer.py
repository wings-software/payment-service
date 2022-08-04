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

import csv
import logging

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.utils.helper_funcs import get_severity_code

from .enrichment import items as prowler_details

severity_dictionary = {
    "PASS": False,
    "INFO": False,
    "FAIL": True,
}

type_dictionary = {
    "1": "Identity and Access Management",
    "2": "Logging",
    "3": "Monitoring",
    "4": "Networking",
}


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        raw_data = binary_data.decode("utf8").splitlines()
        prowler_issues = csv.reader(raw_data, delimiter=",")
        prowler_issues = list(prowler_issues)[2:]

        issues = []
        for issue in prowler_issues:
            title_id = issue[3]
            new_issue = {
                "title_id": title_id,
                "scan_severity": issue[4],
                "issue_name": issue[7],
                "details": issue[8],
                "scored": issue[5],
                "level": issue[6],
            }
            issues.append(new_issue)

        return issues

    def normalizer(self, issue):
        title_id = issue.get("title_id")
        key = title_id
        key_values = ["title_id"]
        scan_severity = issue.get("scan_severity")
        issue_name = issue.get("issue_name")
        details = issue.get("details")
        scored = issue.get("scored")
        level = issue.get("level")

        if level != "Unspecified or Invalid":
            logging.info(level)

        if key not in type_dictionary:
            issue_type = "Not part of CIS benchmark"
            is_cis = False
        else:
            issue_type = type_dictionary[key[0]]
            is_cis = True

        is_issue = severity_dictionary[scan_severity]
        if is_issue:
            if issue["scored"] == "Not Scored":
                severity = 1
            elif issue["level"] == 1 or issue["level"] == "Unspecified or Invalid":
                severity = 8
            else:
                severity = 9
        else:
            return
        severity_code = get_severity_code(severity)

        new_issue = {
            "issue_name": f"{key} {issue_name}",
            "scan_severity": scan_severity,
            "severity_code": severity_code,
            "severity": severity,
            "scored": scored,
            "level": level,
            "key": key,
            "title_id": title_id,
            "key_values": key_values,
            "issue_type": issue_type,
            "issue_description": details,
        }

        if is_cis:
            details = next((obj for obj in prowler_details if obj["key"] == key), {})
            if "key" in details:
                new_issue["implementation"] = details["description"]
                new_issue["guidance"] = details["guidance"]
                new_issue["responsibility"] = details["responsibility"]
                new_issue[
                    "cis_link"
                ] = f'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page={details["page"]}'

        return new_issue
