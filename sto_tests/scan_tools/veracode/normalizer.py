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

import copy
import json
import logging
import os

import xmltodict

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.issue_refinement.refinement.product_info import ScanTypeInfo
from gaussian.utils.text_scrapers import scrape_reference_identifier


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        issues = []
        data = json.loads(json.dumps(xmltodict.parse(binary_data.decode("utf-8"))))
        logging.debug(f"Veracode raw issue {data}")
        if "detailedreport" not in data:
            return []
        report = data.get("detailedreport", {})
        build_id = report.get("@build_id")
        severities = report.get("severity", [])
        # Filter out non dictionary data with no category data
        severities = [
            severity
            for severity in severities
            if isinstance(severity, dict) and "category" in severity
        ]
        # Handle case of length 1
        if isinstance(severities, dict):
            return [severities]
        # Need top level data and nested values
        for severity in severities:
            category = severity.get("category")
            if not isinstance(category, list):
                categories = [category]
            else:
                categories = category

            for item in categories:
                remediation_steps = ""
                recommendations = []
                para = item.get("recommendations", {}).get("para")
                if isinstance(para, dict):
                    recommendations = [para]
                else:
                    recommendations = para
                for entry in recommendations:
                    bullet_items = " ".join(
                        [bi.get("@text", "") for bi in entry.get("bulletitem", [])]
                    )
                    remediation_steps = (
                        f'{remediation_steps}{entry.get("@text")} {bullet_items} '
                    )
                flaws = []
                cwe_data = item.get("cwe", [])
                if isinstance(cwe_data, dict):
                    cwe_data = [cwe_data]
                for cwe_item in cwe_data:
                    static_flaws_data = cwe_item.get("staticflaws", {}).get("flaw", [])
                    dynamic_flaws_data = cwe_item.get("dynamicflaws", {}).get(
                        "flaw", []
                    )
                    if isinstance(static_flaws_data, dict):
                        static_flaws_data = [static_flaws_data]
                    if isinstance(dynamic_flaws_data, dict):
                        dynamic_flaws_data = [dynamic_flaws_data]

                    for cnt in range(len(static_flaws_data)):
                        static_flaws_data[cnt]["scan_type"] = ScanTypeInfo.SAST
                        static_flaws_data[cnt]["build_id"] = build_id
                    for cnt in range(len(dynamic_flaws_data)):
                        dynamic_flaws_data[cnt]["scan_type"] = ScanTypeInfo.DAST
                        dynamic_flaws_data[cnt]["build_id"] = build_id

                    flaws += static_flaws_data
                    flaws += dynamic_flaws_data
                if isinstance(flaws, list):
                    issues.extend(flaws)

        # Extract SCA issues from raw dat if they exist
        try:
            sca_issues = (
                report.get("software_composition_analysis", {})
                .get("vulnerable_components", {})
                .get("component", [])
            )
            # Handle case of length 1
            if isinstance(sca_issues, dict):
                sca_issues = [sca_issues]
            for sca in sca_issues:
                if not isinstance(sca, dict) or "@component_id" not in sca:
                    continue
                if "@vulnerabilities" in sca and not int(sca.get("@vulnerabilities")):
                    continue

                vulns = sca.get("vulnerabilities", {}).get("vulnerability", [])
                if isinstance(vulns, dict):
                    vulns = [vulns]
                if vulns:
                    for vuln in vulns:
                        if isinstance(vuln, dict):
                            new_issue = copy.deepcopy(sca)
                            vuln["scan_type"] = ScanTypeInfo.SCA
                            vuln["build_id"] = build_id
                            new_issue.update(vuln)
                            issues.append(new_issue)
        except (AttributeError):

            sca_issues = []

        return issues

    def normalizer(self, issue):
        # Handle SAST and DAST issues
        scan_type = issue.get("scan_type")
        if scan_type in ["DAST", "SAST"]:
            remediation_status = issue.get("@remediation_status")
            category_name = issue.get("@categoryname")
            if remediation_status in ["New", "Open", "Re-Open"]:
                cwe = f"CWE-{issue.get('@cweid', '')}"
                key = cwe
                key_values = ["cwe"]
                description = issue.get("@description")
                severity = issue.get("@severity")
                exploit_level = issue.get("@exploitlevel")
                module = issue.get("@module")
                line = issue.get("@line")
                scan_type = issue.get("scan_type")
                file = os.path.join(
                    issue.get("@sourcefilepath", ""), issue.get("@sourcefile", "")
                )
                remediation_steps = issue.get("remediation_steps")
                new_issue = {
                    "issue_name": category_name,
                    "issue_description": description,
                    "issue_type": "vulnerability",
                    "severity": self.get_normal_severity_from_veracode_severity(
                        severity
                    ),
                    "exploitability_score": exploit_level,
                    "file_name": file,
                    "line_number": line,
                    "module": module,
                    "remediation_steps": remediation_steps,
                    "scan_type": scan_type,
                    "reference_identifiers": scrape_reference_identifier(cwe),
                    "key": key,
                    "key_values": key_values,
                    "cwe": cwe,
                    "build_id": issue.get("build_id"),
                }
                return {
                    key: value for key, value in new_issue.items() if value is not None
                }
            elif remediation_status in ["Fixed"]:
                logging.debug(
                    f"Ignoring remediated issue found ('{remediation_status}' for '{category_name}')"
                )
            else:
                logging.warning(
                    f"Unrecognized remediation_status '{remediation_status}'"
                )
            return None
        # Handle SCA issues
        elif scan_type == "SCA":
            library = issue.get("@library")
            vendor = issue.get("@vendor")
            file_name = issue.get("@file_name")
            description = issue.get("@cve_summary")
            severity = self.get_normal_severity_from_veracode_severity(
                issue.get("@severity")
            )
            version = issue.get("@version")
            added_date = issue.get("@added_date")
            cve = issue.get("@cve_id")
            cwe = issue.get("@cwe_id")
            file_path = issue.get("file_paths", {}).get("file_path")
            file_paths = []

            if file_path:
                if isinstance(file_path, list):
                    file_paths = [path.get("@value") for path in file_path]
                else:
                    file_paths = [file_path.get("@value", file_name)]

            reference_identifiers = []
            identifiers = []
            if cve and "cve" in cve.lower():
                identifiers.extend(scrape_reference_identifier(cve))
            if cwe and "cwe" in cwe.lower():
                identifiers.extend(scrape_reference_identifier(cwe))
            reference_identifiers.extend(
                [x for x in identifiers if x not in reference_identifiers]
            )
            issue_name = f"{cve} - ({vendor}, {library}, {version})"
            key = f"{library}//{version}"
            key_values = ["library_name", "current_version"]
            new_issue = {
                "issue_name": issue_name,
                "issue_description": description,
                "library_name": library,
                "issue_type": "vulnerability",
                "severity": severity,
                "exploitability_score": None,
                "file_name": file_path,
                "file_paths": file_paths,
                "line_number": None,
                "reference_identifiers": reference_identifiers,
                "key": key,
                "key_values": key_values,
                "scan_type": scan_type,
                # additional data
                "build_id": issue.get("build_id"),
                "vendor": vendor,
                "current_version": version,
                "added_date": added_date,
            }
            return {key: value for key, value in new_issue.items() if value is not None}
        else:
            logging.error("Invalid scan_type of {scan_type}")
            return None

    @classmethod
    def get_normal_severity_from_veracode_severity(cls, scan_severity):
        if scan_severity == "0":
            return 0
        elif scan_severity == "1":  # Very Low
            return 1
        elif scan_severity == "2":  # Low
            return 3
        elif scan_severity == "3":  # Medium
            return 4
        elif scan_severity == "4":  # High
            return 8
        elif scan_severity == "5":  # Critical
            return 10
        else:
            logging.info(f"Unknown Severity Level: {scan_severity}")
            return -1


def getVulnDetails(issue):
    line = issue["line_number"]
    file_name = issue["file_name"]
    exploitability_score = issue["exploitability_score"]
    severity = issue["severity"]
    return {
        "lineNumber": line,
        "fileName": file_name,
        "exploitabilityScore": exploitability_score,
        "severity": severity,
    }
