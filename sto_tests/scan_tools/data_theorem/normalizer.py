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
import json

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC

severity_dictionary_enum = {
    "INFO": "Information",
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
}
severity_dictionary = {"INFO": 0, "LOW": 3, "MEDIUM": 6, "HIGH": 8, "CRITICAL": 10}


class Refiner(RefinerABC):
    def __init__(self) -> None:
        self.app_name = ""
        self.platform = ""
        self.scan_date = ""
        self.app_version = ""
        self.package_id = ""
        self.release_type = ""
        self.app_id = ""
        self.is_csv = False
        super().__init__()

    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        try:
            dt_issues = None
            try:
                dt_issues = json.loads(binary_data.decode("utf8"))
            except Exception:
                raw_data = binary_data.decode("utf-8").splitlines()
                dt_issues = csv.reader(raw_data, delimiter=",")
                self.is_csv = True

            dt_issues = list(dt_issues)

            if self.is_csv:
                self.app_name = ((str)(dt_issues[0])).split(":")[1].split("'")[0]
                self.platform = (str)(dt_issues[1]).split(":")[1].split("'")[0]
                self.scan_date = (str)(dt_issues[2]).split(":")[1].split("'")[0]
                self.app_version = (str)(dt_issues[3]).split(":")[1].split("'")[0]
                self.package_id = (str)(dt_issues[4]).split(":")[1].split("'")[0]
                self.release_type = (str)(dt_issues[5]).split(":")[1].split("'")[0]
                dt_issues = dt_issues[7:]
            else:
                self.app_id = dt_issues[0].get("mobile_app_id")
                self.scan_date = dt_issues[0].get("results_last_updated")

            return dt_issues
        except Exception as ex:
            config.logger.error(ex, exc_info=True)
            raise

    def normalizer(self, issue):
        new_issue = {}
        if self.is_csv:
            new_issue = process_issue_from_csv(issue)
        else:
            new_issue = process_issue_from_json(issue)

        if new_issue.get("aggregated_status", "open").lower() != "open":
            return

        new_issue["app_id"] = self.app_id
        new_issue["app_version"] = self.app_version
        new_issue["app_name"] = self.app_name
        new_issue["platform"] = self.platform
        new_issue["scan_date"] = self.scan_date
        new_issue["package_id"] = self.package_id
        new_issue["release_type"] = self.release_type

        return new_issue


def process_issue_from_json(issue):
    issue_id = issue.get("id")
    category = issue.get("category")
    title = issue.get("title")
    severity = issue.get("severity")
    exploitability = issue.get("exploitability")
    status = issue.get("aggregated_status")
    description = issue.get("description")
    portal_url = issue.get("portal_url")
    secure_code = issue.get("secure_code", "None")
    recommendation = issue.get("recommendation")

    new_issue = {
        "issue_name": title,
        "issue_description": description,
        "scan_severity": severity_dictionary_enum[severity],
        "severity": severity_dictionary[severity],
        "raw_severity": severity,
        "status": status,
        "aggregated_status": status,
        "exploitability": exploitability,
        "issue_id": issue_id,
        "key": issue_id,
        "key_values": ["issue_id"],
        "category": category,
        "recommendation": recommendation,
        "secure_code": secure_code,
        "url": portal_url,
    }

    return new_issue


def process_issue_from_csv(issue):
    issue_id = issue[0]
    category = issue[1]
    title = issue[2]
    severity = issue[3]
    exploitability = issue[6]
    status = issue[7]
    aging = issue[8]
    description = issue[9]
    cvssScore = issue[4]
    reproduction = issue[10]
    recommendation = issue[11]

    new_issue = {
        "issue_name": title,
        "issue_description": description,
        "scan_severity": severity_dictionary_enum[severity],
        "severity": severity_dictionary[severity],
        "issue_id": issue_id,
        "key": issue_id,
        "key_values": ["issue_id"],
        "status": status,
        "aggregated_status": status,
        "cvss": cvssScore,
        "exploitability": exploitability,
        "category": category,
        "reproduction": reproduction,
        "recommendation": recommendation,
        "aging": aging,
    }
    return new_issue
