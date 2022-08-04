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
import string

import charset_normalizer
import dateutil.parser
import xmltodict

from gaussian.utils.helper_funcs import is_number, strip_cwe_cve, timestamp_microsecond

from ...abc.refiner import RefinerABC


def lookup(data, group, key):
    group_key = f"{group}-group"
    return data.get(group_key, {}).get(key, {})


class Refiner(RefinerABC):
    def __init__(self):
        self.lookups = {}

    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        detect_encoding = charset_normalizer.detect(binary_data)
        config.logger.info(f"File Encoding: {detect_encoding}")
        raw_data = binary_data.decode(detect_encoding.get("encoding", "UTF-8")).strip()
        filtered_string = "".join(filter(lambda x: x in string.printable, raw_data))

        if filtered_string[:1] == "<":
            raw_data = json.dumps(xmltodict.parse(filtered_string))
        else:
            raw_data = filtered_string

        raw_data = json.loads(raw_data)
        report = raw_data.get("xml-report", [])

        for key in list(report.keys()):
            contents = []
            if "-group" in key and report is not None:
                try:
                    contents = report.get(key, {}).get("item", [])
                    if contents is None:
                        contents = []
                        pass
                except BaseException:
                    pass

                self.lookups[key] = {}

                for c in contents:
                    if isinstance(c, str):
                        continue

                    report_id = c.get("@id", None)

                    if report_id is not None:
                        try:
                            self.lookups[key][report_id] = c
                        except BaseException:
                            pass

        # Grab the run-time from the xml
        try:
            scan_date = raw_data["xml-report"]["scan-information"]["scan-date-and-time"]
            job_runtime = timestamp_microsecond(dateutil.parser.parse(scan_date)) * 1000
        except Exception as e:
            job_runtime = None
            config.logger.info(f"Cannot parse scan submission date: {e}", exc_info=True)

        if "item" in report["issue-group"]:
            issues = report["issue-group"]["item"]
        else:
            issues = []

        result_dict = {}
        result_dict["issues"] = issues
        if job_runtime is not None:
            result_dict["job_runtime"] = job_runtime
        result_dict["extra_data"] = {}

        return result_dict

    def normalizer(self, issue):
        new_issue = {}
        new_issue["scan_severity"] = issue.get("severity", 0)
        new_issue["cvss"] = issue.get("cvss-score", 0)
        severity = new_issue["cvss"]

        if is_number(severity):
            severity = float(severity)
        else:
            severity = -1

        new_issue["severity"] = severity

        issue_type = lookup(
            self.lookups,
            "issue-type",
            issue.get("issue-type", {}).get("ref"),
        )
        new_issue["issue_name"] = issue_type.get("name", "")

        cve = issue_type.get("cve", None)
        cwe = issue.get("cwe", None)
        if cwe is None:
            cwe = issue_type.get("cwe", None)

        new_issue["fix_recommendation_raw"] = lookup(
            self.lookups,
            "fix-recommendation",
            issue_type.get("fix-recommendation", {}).get("ref"),
        )
        new_issue["fix_recommendation"] = (
            new_issue["fix_recommendation_raw"]
            .get("general", {})
            .get("fixRecommendation", {})
            .get("text")
        )

        new_issue["remediation_raw"] = lookup(
            self.lookups,
            "remediation",
            issue.get("remediation", {}).get("ref"),
        )
        new_issue["remediation"] = new_issue.get("remediation_raw", {}).get("name")

        new_issue["advisory"] = lookup(
            self.lookups,
            "advisory",
            issue.get("advisory", {}).get("ref"),
        )
        advisory_data = new_issue["advisory"].get("advisory", {})
        new_issue["issue_description"] = " ".join(
            advisory_data.get("testTechnicalDescription", {}).get("text", []),
        )

        xfid = advisory_data.get("xfid", {}).get("link", {}).get("@id")

        causes = advisory_data.get("causes", {}).get("cause", [])
        if not isinstance(causes, (list,)):
            causes = [causes]

        new_issue["causes_raw"] = [lookup(self.lookups, "cause", x) for x in causes]
        new_issue["causes"] = [
            c["#text"] for c in new_issue["causes_raw"] if "#text" in c
        ]

        threat_class = lookup(
            self.lookups,
            "threat-class",
            issue.get("threat-class", {}).get("ref"),
        )
        new_issue["threat_class"] = threat_class.get("#text")
        new_issue["threat_class_href"] = threat_class.get("@href")

        security_risks = issue.get("security-risks", {}).get("ref")
        if not isinstance(security_risks, (list,)):
            security_risks = [security_risks]

        new_issue["security_risks"] = [
            lookup(self.lookups, "security-risk", x).get("#text")
            for x in security_risks
        ]

        entity_raw = lookup(self.lookups, "entity", issue.get("entity", {}).get("ref"))
        entity_name = entity_raw.get("name")

        new_issue["entity_name"] = entity_name
        new_issue["entity_type"] = entity_raw.get("entity-type")
        new_issue["entity_url"] = entity_raw.get("url-name")

        url_raw = lookup(self.lookups, "url", issue.get("url", {}).get("ref"))
        new_issue["url_name"] = url_raw.get("name")

        identifiers = []

        if cwe:
            identifiers.append({"type": "cwe", "id": cwe})
        if cve:
            identifiers.append({"type": "cve", "id": strip_cwe_cve(cve)})
        if xfid:
            identifiers.append({"type": "xfid", "id": xfid})

        new_issue["reference_identifiers"] = identifiers

        try:
            key = new_issue["advisory"]["@id"]
            issue_id = new_issue["advisory"]["@id"]
        except Exception:
            key = issue.get("@id")
            issue_id = issue.get("@id")
        new_issue["key"] = key
        new_issue["issue_id"] = issue_id
        new_issue["key_values"] = ["issue_id"]
        return new_issue

    def supplemental_data(self, config, binary_data, extra_data):
        pass
