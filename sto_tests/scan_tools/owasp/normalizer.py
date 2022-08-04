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

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.issue_refinement.refinement.product_info import ScanTypeInfo
from gaussian.utils.text_scrapers import scrape_reference_identifier


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):

        issues = []
        owasp_data = json.loads(binary_data.decode("utf8"))

        dependencies = owasp_data["dependencies"]
        if not isinstance(dependencies, list):
            dependencies = [dependencies]

        for dependency in dependencies:
            vulnerabilities = dependency.get("vulnerabilities", [])

            if not isinstance(vulnerabilities, list):
                vulnerabilities = []

            if not vulnerabilities:
                continue

            evidence = dependency.get("evidenceCollected", {})

            product_evidence = evidence.get("productEvidence", [])
            if not isinstance(product_evidence, list):
                product_evidence = []

            version_evidence = evidence.get("versionEvidence", [])
            if not isinstance(version_evidence, list):
                version_evidence = []

            file_name = dependency.get("fileName")
            file_path = dependency.get("filePath")
            key = f"{file_name}"
            key_values = ["file_name"]

            products = [
                x for x in product_evidence if x["name"].lower() == "artifactid"
            ]
            if not products:
                products = [x for x in product_evidence if x["name"].lower() == "name"]

            if products:
                highest_product = [
                    x for x in products if x["confidence"].lower() == "highest"
                ]
                if len(highest_product) > 0:
                    product = highest_product[0].get("value", "").lower()
                else:
                    product = products[0].get("value", "").lower()
            else:
                product = ""

            versions = [x for x in version_evidence if x["name"].lower() == "version"]

            if versions:
                highest_version = [
                    x for x in versions if x["confidence"].lower() == "highest"
                ]
                if len(highest_version) > 0:
                    version = highest_version[0].get("value", "").lower()
                else:
                    version = versions[0].get("value", "").lower()
            else:
                version = ""

            if version != "" and product != "":
                key = f"{product}//{version}"
                key_values = ["product", "current_version"]
            elif product != "":
                key = product
                key_values = ["product"]

            for issue in vulnerabilities:
                issue["issue_name"] = key
                issue["file_path"] = file_path
                issue["file_name"] = file_name
                issue["product"] = product
                issue["current_version"] = version
                issue["key"] = key
                issue["key_values"] = key_values
                issues.append(issue)
        return issues

    def normalizer(self, issue):
        cvss_str = 0
        if issue.get("cvssScore") is not None:
            cvss_str = issue.get("cvssScore", 0)
        elif issue.get("cvssv3", {}).get("baseScore") is not None:
            cvss_str = issue.get("cvssv3", {}).get("baseScore", 0)
        # Some vulns only have CVSS V2 scores. We will use this information if
        # it is the only score available
        elif issue.get("cvssv2", {}).get("score") is not None:
            cvss_str = issue.get("cvssv2", {}).get("score", 0)
        cvss = 0.0

        try:
            cvss = float(cvss_str)
        except Exception:  # noqa: S110
            pass

        scan_severity = issue.get("severity")

        if cvss > 0.0:
            if cvss < 1.0:
                scan_severity = "Info"
            elif cvss < 4.0:
                scan_severity = "Low"
            elif cvss < 7.0:
                scan_severity = "Medium"
            elif cvss < 9.0:
                scan_severity = "High"
            else:
                scan_severity = "Critical"
        else:
            scan_severity_lower = str(scan_severity).lower()
            if scan_severity_lower is None or scan_severity_lower == "None":
                scan_severity = "Info"
                cvss = 0.0
            elif scan_severity_lower == "low":
                scan_severity = "Low"
                cvss = 2.0
            # Some of the NPM packages were marked as moderate instead of medium
            elif scan_severity_lower == "moderate" or scan_severity_lower == "medium":
                scan_severity = "Medium"
                cvss = 5.0
            elif scan_severity_lower == "high":
                scan_severity = "High"
                cvss = 8.0
            elif scan_severity_lower == "critical":
                scan_severity = "Critical"
                cvss = 10.0
            else:
                scan_severity = "Info"
                cvss = 0.0
                logging.info(
                    f"OWASP - Unknown Severity Level: {scan_severity} for CVSS Score: {cvss}",
                )
            logging.info(
                f"OWASP - Set CVSS based on text severity : {scan_severity} for CVSS Score: {cvss}",
            )

        # gather reference_identifier
        identifiers = []
        cwe = issue.get("cwe", None)
        new_identifiers = scrape_reference_identifier(cwe)
        identifiers.extend([x for x in new_identifiers if x not in identifiers])
        cve = issue.get("name", None)
        new_identifiers = scrape_reference_identifier(cve)
        identifiers.extend([x for x in new_identifiers if x not in identifiers])
        raw_references = issue.get("references", [])
        if not isinstance(raw_references, list):
            raw_references = [raw_references]
        references = []
        for ref in raw_references:
            if ref not in references:
                references.append(ref)
        for reference in references:
            new_identifiers = scrape_reference_identifier(
                reference.get("name", None),
            )
            identifiers.extend(
                [x for x in new_identifiers if x not in identifiers],
            )

        # prune reference duplicates

        return {
            "issue_name": f'{issue.get("product")}@{issue.get("current_version")}',
            "file_name": issue.get("file_name"),
            "file_path": issue.get("file_path"),
            "key": issue.get("key"),
            "product": issue.get("product"),
            "library_name": issue.get("product"),
            "current_version": issue.get("current_version"),
            "cvss": cvss,
            "description": issue.get("description"),
            "notes": issue.get("notes"),
            "references": references,
            "vulnerable_versions": issue.get("vulnerableSoftware"),
            "severity": cvss,
            "scan_severity": scan_severity,
            "reference_identifiers": identifiers,
            "scan_type": ScanTypeInfo.SCA,
        }
