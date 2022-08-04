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
from gaussian.utils.helper_funcs import strip_cwe_cve, try_parse_int


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        try:
            return json.loads(binary_data.decode("utf-8").strip())
        except Exception as ex:
            config.logger.error(ex, exc_info=True)
            raise

    def normalizer(self, issue):
        cwe_regex = r"cwe\.mitre\.org\/data\/definitions\/([0-9]*)\.html"
        cve_regex = "vulnId=CVE-([0-9,-]*)"
        cve_regex2 = "'refId': 'CVE-([0-9,-]*)'"
        nsa_regex = r'https:\/\/nodesecurity\.io\/advisories\/([0-9]*)"'

        if not issue.get("securityData", {}).get("securityIssues"):
            return

        issue_hash = issue.get("hash")
        identifier = issue.get("componentIdentifier").get("coordinates")
        current_version = identifier.get("version")
        if "name" in identifier and "version" in identifier:
            key = identifier["name"] + "//" + current_version
            key_values = ["library_name", "current_version"]
            current_version = identifier.get("version")
            name = identifier["name"]
        elif "packageId" in identifier and "version" in identifier:
            key = identifier["packageId"] + "//" + current_version
            key_values = ["library_name", "current_version"]
            current_version = identifier.get("version")
            name = identifier["packageId"]
        elif "artifactId" in identifier and "version" in identifier:
            key = identifier["artifactId"] + "//" + current_version
            key_values = ["library_name", "current_version"]
            name = identifier["artifactId"]
        else:
            key = "undefinedPackageName:" + issue_hash
            key_values = ["hash"]
            name = key

        max_severity = 0
        vulnerability_details = []
        issue_license = []
        reference_identifiers = []

        vuln_details = issue.get("securityData", {}).get("securityIssues")
        cwe = []
        cve = []
        nsa = []

        for vuln in vuln_details:
            if not isinstance(vuln, dict):
                continue

            reference = vuln.get("reference", None)
            severity = vuln.get("severity", 0)
            scan_severity = vuln.get("threatCategory", None)
            manual_upload = False

            html = vuln.get("details", {}).get("body", {}).get("htmlDetails", "")

            details = {
                "reference": reference,
                "severity": severity,
                "scanSeverity": scan_severity,
                "details": html,
            }

            if details not in vulnerability_details:
                vulnerability_details.append(details)

            max_severity = max(max_severity, severity)

            if manual_upload:

                if "CVE-" in reference:
                    cve.append(strip_cwe_cve(reference))
                elif "CWE-" in reference:
                    cwe.append(strip_cwe_cve(reference))
            else:
                cwe_scrape = re.findall(cwe_regex, html)
                cve_scrape = re.findall(cve_regex, html)
                cve_scrape2 = re.findall(cve_regex2, html)
                nsa_scrape = re.findall(nsa_regex, html)

                if cwe_scrape:
                    cwe += cwe_scrape
                if cve_scrape:
                    cve += cve_scrape
                if cve_scrape2:
                    cve += cve_scrape2
                if nsa_scrape:
                    nsa += nsa_scrape

        reference_identifiers.extend(
            [
                {"type": "cwe", "id": try_parse_int(vuln_id)}
                for vuln_id in list(set(cwe))
            ]
        )
        reference_identifiers.extend(
            [{"type": "cve", "id": vuln_id} for vuln_id in list(set(cve))]
        )
        reference_identifiers.extend(
            [
                {"type": "nsa", "id": try_parse_int(vuln_id)}
                for vuln_id in list(set(nsa))
            ]
        )

        issue_license += list(
            map(lambda x: x["licenseId"], issue["licenseData"]["declaredLicenses"]),
        )

        if issue.get("matchState", "exact") != "exact":
            max_severity = 0

        return {
            "issue_name": key,
            "severity": max_severity,
            "issue_description": f"{len(vulnerability_details)} issues detected",
            "vulnerability_details": vulnerability_details,
            "reference_identifiers": reference_identifiers,
            "cvss": max_severity,
            "project": name,
            "license": issue_license,
            "file_name": issue["pathnames"],
            "library_name": name,
            "current_version": current_version,
            "key": key,
            "key_values": key_values,
            "hash": issue_hash,
        }
