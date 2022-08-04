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
from gaussian.utils.helper_funcs import strip_cwe_cve


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        json_data = json.loads(binary_data.decode("utf8"))

        if "alerts" in json_data:
            return [alert for alert in json_data["alerts"] if "vulnerability" in alert]
        else:
            logging.info("No issues found.")
            return []

    def normalizer(self, issue):
        library = issue.get("library", {})
        file_name = library.get("filename", "")
        library_name = library.get("name")
        current_version = library.get("version")
        vulnerability = issue.get("vulnerability", {})
        v_name = vulnerability.get("name", "").lower()
        reference_identifiers = []
        remediation_steps = []
        key = f"{library_name}//{current_version}"
        # nested key value
        key_values = ["library_name", "current_version"]
        vulnerability_details = []
        remediation_steps = []
        max_cvss2 = -1
        max_cvss3 = -1
        issue_type = ""
        author = ""
        project = ""
        issue_description = ""

        if "ws" in v_name:
            reference_identifiers.append({"type": "ws", "id": strip_cwe_cve(v_name)})
        elif vulnerability.get("type") == "CVE":
            reference_identifiers.append({"type": "cve", "id": strip_cwe_cve(v_name)})
        vul_description = vulnerability.get("description")
        cvss2 = vulnerability.get("score")
        cvss3 = vulnerability.get("cvss3_score", -1)

        cvss2_str = f"CVSS v2: {cvss2}"
        cvss3_str = ""
        if cvss3 > -1:
            cvss3_str = f", CVSS v3: {cvss3}"
        else:
            cvss3_str = ", CVSS v3: Not Reported"

        vulnerability_details.append(
            f"Severity: ({cvss2_str}{cvss3_str}); Description: {vul_description}",
        )

        max_cvss2 = max(cvss2, max_cvss2)
        max_cvss3 = max(cvss3, max_cvss3)

        vulnerability_fix_message = vulnerability.get("vulnerabilityFix", {}).get(
            "message", ""
        )
        resolution_text = vulnerability.get("fixResolutionText", "")

        author = issue.get("library", {}).get("owner")
        project = issue.get("project")
        scan_severity = issue.get("level")
        remediation_steps.append(
            f"{vulnerability_fix_message} {resolution_text}",
        )
        issue_type = issue.get("type")
        issue_description = issue.get("description")

        if ".tgz" in key and re.search(r"\.tgz$", key) is not None:
            key = re.sub(r"\.tgz$", "", key)

        if max_cvss3 > -1:
            # if we have cvss3 use it
            max_cvss = max_cvss3
            cvss_version = "CVSS v3"
        else:
            # otherwise, fallback to cvss2
            # and add a flag so the UI can
            # make the customer aware
            max_cvss = max_cvss2
            cvss_version = "CVSS v2"
        return {
            "issue_name": key,
            "issue_description": issue_description,
            "issue_type": issue_type,
            "author": author,
            "file_name": file_name,
            "library_name": library_name,
            "current_version": current_version,
            "scan_severity": scan_severity,
            "project": project,
            "cvss": max_cvss,
            "severity": max_cvss,
            "cvss_version": cvss_version,
            "remediation_steps": remediation_steps,
            "vulnerability_details": vulnerability_details,
            "reference_identifiers": reference_identifiers,
            "key": key,
            "key_values": key_values,
        }
