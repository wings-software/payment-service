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
import logging
import re

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.issue_refinement.refinement.product_info import ScanTypeInfo
from gaussian.utils.helper_funcs import (
    get_severity_code,
    strip_cwe_cve,
    strip_node_security,
    strip_temp,
)

severity_dictionary = {
    "INFO": 0,
    "LOW": 3,
    "MINOR": 3,
    "MEDIUM": 6,
    "MAJOR": 6,
    "HIGH": 8,
    "CRITICAL": 10,
}


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        issues = []
        json_data = json.loads(binary_data.decode("utf8"))

        if len(json_data) == 0:
            return []
        for data in json_data:
            if "ruleSet" in data:
                for rules in data["ruleSet"]:
                    try:
                        twistlock_issues = []
                        if len(rules["images"]):
                            twistlock_issues = rules.get("images")
                        elif len(rules["hosts"]):
                            twistlock_issues = rules.get("hosts")
                        elif len(rules["containers"]):
                            twistlock_issues = rules.get("containers")
                    except KeyError:
                        config.logger.info(
                            f"Twistlock - No CVE Vulnerabilities: {data}"
                        )
                        return issues
            else:
                twistlock_issues = json_data
                if "results" in twistlock_issues:
                    twistlock_issues = twistlock_issues.get("results")
                for item in twistlock_issues:
                    if "info" in item:
                        if isinstance(item, str):
                            values = json.loads(item)
                            cve_vulns = values["images"][0]["info"][
                                "cveVulnerabilities"
                            ]
                        else:
                            cve_vulns = item["info"]["cveVulnerabilities"]

                    elif "cveVulnerabilities" in item:
                        cve_vulns = item.get("cveVulnerabilities")
                    elif "vulnerabilities" in item:
                        cve_vulns = item.get("vulnerabilities")
                    elif "entityInfo" in item:
                        cve_vulns = item.get("entityInfo").get("vulnerabilities")
                    else:
                        raise KeyError("The json data is missing vulnerability data")

                    if cve_vulns is None:
                        continue

                    product = item.get("host", "")
                    if "host" in item:
                        product = item.get("host")

                    if "image" in item:
                        product = item.get("image")

                    for vuln in cve_vulns:
                        if isinstance(vuln, dict):
                            vuln["product"] = product
                    issues.extend(cve_vulns)

        return issues

    def normalizer(self, issue):
        vulns_description = issue.get("description")
        if "exploit" in issue:
            issue_exploit = issue.get("exploit")
        else:
            issue_exploit = None
        issue_link = issue.get("link")
        issue_package_name = issue.get("packageName")
        issue_package_version = issue.get("packageVersion")
        scan_severity = issue.get("severity").lower()
        issue_type = issue.get("type")
        if "vecStr" in issue:
            issue_vector = issue.get("vecStr")
        elif "vector" in issue:
            issue_vector = issue.get("vector")
        else:
            issue_vector = None
        issue_cvss = issue.get("cvss", -1)
        issue_product = issue.get("product")

        key = f"{issue_package_name}//{issue_package_version}"
        key_values = ["library_name", "current_version"]
        library_name = f"{issue_package_name}"

        cvss_suggested_severity = get_severity_code(issue_cvss).lower()

        if cvss_suggested_severity == scan_severity:
            severity = issue_cvss
        else:
            if scan_severity == "unimportant" or scan_severity == "not yet assigned":
                severity = 0
            elif scan_severity == "low" or scan_severity == "unknown":
                severity = 3
            elif scan_severity == "medium":
                severity = 6
            elif scan_severity == "high" or "important":
                severity = 8
            elif scan_severity == "critical":
                severity = 10
            else:
                severity = -1
                logging.info(
                    f"Twistlock - Unknown Severity Level: {severity}",
                )

        reference_identifiers = []

        cves = list(set(issue.get("cve", [])))
        if cves and "" not in cves:
            reference_identifiers += [
                {"type": "cve", "id": strip_cwe_cve(vuln_id)} for vuln_id in cves
            ]

        node_issues = list(set(issue.get("node", [])))
        if node_issues and "" not in node_issues:
            reference_identifiers += [
                {
                    "type": "node-security",
                    "id": strip_node_security(vuln_id),
                }
                for vuln_id in node_issues
            ]

        temp_issues = list(set(issue.get("temp", [])))
        if temp_issues and "" not in temp_issues:
            reference_identifiers += [
                {"type": "temp", "id": strip_temp(vuln_id)} for vuln_id in temp_issues
            ]

        if "+" in key:
            key = re.sub(r"\+(.*)$", "", key)

        if ".el" in key and re.search(r"\.el(.*)$", key) is not None:
            key = re.sub(r"\.el(.*)$", "", key)

        return {
            "description": vulns_description,
            "severity": severity,
            "library_name": library_name,
            "current_version": issue_package_version,
            "reference_identifiers": reference_identifiers,
            "exploit": issue_exploit,
            "link": issue_link,
            "issue_type": issue_type,
            "vector": issue_vector,
            "product": issue_product,
            "issue_name": key,
            "key": key,
            "key_values": key_values,
            "scan_type": ScanTypeInfo.SCA,
        }

    def supplemental_data(self, config, binary_data, target=None, policy=None):
        issues = []
        extra_data = {}
        json_data = json.loads(binary_data.decode("utf8"))

        if len(json_data) == 0:
            return []

        for data in json_data:
            if "ruleSet" in data:
                rule_name = data.get("ruleName")

                for rules in data["ruleSet"]:
                    if rules["ruleId"] == "":
                        continue

                    try:
                        twistlock_issues = []
                        if len(rules["images"]):
                            twistlock_issues = rules.get("images")
                            compliance_object_type = "I"
                        elif len(rules["hosts"]):
                            twistlock_issues = rules.get("hosts")
                            compliance_object_type = "H"
                        elif len(rules["containers"]):
                            twistlock_issues = rules.get("containers")
                            compliance_object_type = "C"
                    except KeyError:
                        config.logger.info(
                            f"Twistlock - No CVE Vulnerabilities: {data}",
                        )
                        return issues
            else:
                twistlock_issues = json_data

                for item in twistlock_issues:
                    if "compliance" not in item:
                        continue

                    compliance = item["compliance"]

                    for issue in compliance:
                        twistlock_rule_id = issue.get("id")
                        scan_severity = None

                        if compliance_object_type == "I":
                            compliance_object = item.get("image", "")
                        elif compliance_object_type == "H":
                            compliance_object = item.get("host", "")
                        elif compliance_object_type == "C":
                            compliance_object = item.get("name", "")

                        issue_package_name = issue["title"]
                        scan_severity = issue["severity"].lower()

                        key = f"{issue_package_name}//{twistlock_rule_id}//{rule_name}"
                        key_values = ["library_name", "issue_id", "rule_name"]

                        if not item.get("image", "").split("/")[1:2]:
                            image_namespace = ""
                        else:
                            image_namespace = item.get("image", "").split("/")[1:2][0]

                        issues.append(
                            {
                                "issue_name": issue_package_name,
                                "issue_id": twistlock_rule_id,
                                "library_name": issue_package_name,
                                "issue_description": issue["description"],
                                "issue_type": "COMPLIANCE",
                                "scan_severity": scan_severity,
                                "current_version": item.get("distro", ""),
                                "host": item.get("host", ""),
                                "image_namespace": image_namespace,
                                "project": item.get("pkgDistroRelease", ""),
                                "package_distro": item.get("pkgDistro", ""),
                                "severity": severity_dictionary.get(
                                    scan_severity.upper(),
                                    -1,
                                ),
                                "rule_name": rule_name,
                                "twistlock_rule_id": twistlock_rule_id,
                                "compliance_issue_package_version": issue[
                                    "packageVersion"
                                ],
                                "compliance_issue_type": issue.get("type", ""),
                                "compliance_issue_cause": data.get("cause"),
                                "image_tag": item.get("tag", ""),
                                "image_repo": item.get("repo", ""),
                                "image_registry": item.get("registry", ""),
                                "compliance_object": [compliance_object],
                                "key": key,
                                "key_values": key_values,
                            }
                        )

        return {"issues": issues, "extra_data": extra_data}
