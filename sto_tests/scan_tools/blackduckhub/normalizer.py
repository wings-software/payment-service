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
from gaussian.issue_refinement.refinement.product_info import ScanTypeInfo
from gaussian.utils.helper_funcs import get_value
from gaussian.utils.text_scrapers import scrape_reference_identifier


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        raw_data = binary_data.decode("utf-8").strip()
        raw_data = json.loads(raw_data)
        issues = raw_data["items"]

        issue_map = {}
        for issue in issues:
            c_name = issue.get("componentName", "no-name")
            c_vers = issue.get("componentVersionName", "no-version")

            project = c_name + "@" + c_vers

            if project not in issue_map:
                issue_map[project] = []

            issue_map[project].append(issue)

        issue_agg = []
        for project in issue_map:
            data = {}
            data["project"] = project
            for data in issue_map[project]:
                issue_agg.append(data)

        return issue_agg

    def normalizer(self, issue):
        vuln = issue
        vulnerability_details = []
        max_cvss = -1
        max_explt = -1
        max_impact = -1
        max_scan_severity = ""
        identifiers = []

        library_name = get_value(vuln, ["componentName"], False)
        current_version = get_value(vuln, ["componentVersionName"], False)

        link = get_value(vuln, ["componentVersion"], False)
        product = get_value(vuln, ["componentVersionOriginName"], False)
        project = get_value(vuln, ["componentVersionOriginId"], False)
        ri_license = vuln.get("license")

        issue_name = f"{library_name} {current_version}"
        key = f"{library_name}//{current_version}"
        key_values = ["library_name", "current_version"]

        vuln_description = get_value(
            vuln,
            ["vulnerabilityWithRemediation", "description"],
        )
        vuln_name = get_value(
            vuln,
            ["vulnerabilityWithRemediation", "vulnerabilityName"],
        )
        scan_status = get_value(
            vuln,
            ["vulnerabilityWithRemediation", "remediationStatus"],
        )
        cvss = get_value(vuln, ["vulnerabilityWithRemediation", "baseScore"])
        if type(cvss) == str:
            cvss = float(cvss)

        scan_explt = get_value(
            vuln,
            ["vulnerabilityWithRemediation", "exploitabilitySubscore"],
        )
        if type(scan_explt) == str:
            scan_explt = float(scan_explt)

        scan_impact = get_value(
            vuln,
            ["vulnerabilityWithRemediation", "impactSubscore"],
        )
        if type(scan_impact) == str:
            scan_impact = float(scan_impact)

        scan_severity = get_value(vuln, ["vulnerabilityWithRemediation", "severity"])

        vulnerability_details.append(
            f"Severity: {scan_severity}; cvss ({cvss}); "
            f"Exploitability ({scan_explt}); Impact ({scan_impact}); "
            f"Description: {vuln_description} ({vuln_name})"
        )

        # grab reference_identifier
        cwe_id = get_value(vuln, ["vulnerabilityWithRemediation", "cweId"], False)
        identifiers.extend(
            scrape_reference_identifier(cwe_id, prefix=["CVE", "CWE", "BDSA"])
        )
        vuln_name = get_value(
            vuln,
            ["vulnerabilityWithRemediation", "vulnerabilityName"],
            False,
        )
        identifiers.extend(
            scrape_reference_identifier(vuln_name, prefix=["CVE", "CWE", "BDSA"]),
        )
        identifiers.extend(
            scrape_reference_identifier(
                vuln_description,
                prefix=["CVE", "CWE", "BDSA"],
            ),
        )

        if cvss > max_cvss:
            max_cvss = max(max_cvss, cvss)
            max_scan_severity = scan_severity

        max_explt = max(max_explt, scan_explt)
        max_impact = max(max_impact, scan_impact)

        # dedup the identifiers
        identifiers = [dict(t) for t in set([tuple(d.items()) for d in identifiers])]

        return {
            "issue_name": issue_name,
            "project": project,
            "product": product,
            "link": link,
            "ri_license": ri_license,
            "library_name": library_name,
            "current_version": current_version,
            "scan_type": ScanTypeInfo.SCA,
            "reference_identifiers": identifiers,
            "scan_severity": max_scan_severity,
            "scan_status": scan_status,
            "severity": max_cvss,
            "exploitability_score": max_explt,
            "impact_score": max_impact,
            "cvss": max_cvss,
            "vulnerability_details": vulnerability_details,
            "key": key,
            "key_values": key_values,
        }
