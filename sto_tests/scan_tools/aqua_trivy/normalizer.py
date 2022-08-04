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

from gaussian.utils.text_scrapers import scrape_reference_identifier

from ...abc.refiner import RefinerABC


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        data = json.loads(binary_data)
        if isinstance(data, dict):
            data = data.get("Results", [])

        target_issues = []
        for target_data in data:
            try:
                vulnerabilities = target_data.get("Vulnerabilities", [])
                if not vulnerabilities:
                    continue
                for issue in vulnerabilities:
                    issue["Target"] = target_data.get("Target")
                    issue["Class"] = target_data.get("Class")
                    issue["Type"] = target_data.get("Type")
                    target_issues.append(issue)
            except Exception as err:
                config.logger.error(err)
                raise Exception(
                    f"Error extracting Aqua Trivy vulnerabilities from raw_issues. Error: {err}",
                )

        return {"issues": target_issues, "extra_data": {}}

    def normalizer(self, issue):
        target = issue.get("Target")
        title = issue.get("Title")
        issue_class = issue.get("Class")
        issue_type = issue.get("Type")
        description = issue.get("Description")
        vulnerability_code = issue.get("VulnerabilityID")
        installed_version = issue.get("InstalledVersion")
        fixed_version = issue.get("FixedVersion")
        package_name = issue.get("PkgName")

        key_values = ["vulnerability_code"]
        key = "//".join([vulnerability_code])
        if package_name:
            title = f"{package_name}@{installed_version} ({issue_class}, {issue_type})"
            key_values = ["library_name", "current_version"]
            key = "//".join([package_name, installed_version])

        reference_ids = scrape_reference_identifier(
            vulnerability_code,
            prefix=["CVE", "CWE", "TEMP"],
        )
        reference_ids.extend(
            scrape_reference_identifier(title, prefix=["CVE", "CWE", "TEMP"]),
        )
        reference_ids.extend(
            scrape_reference_identifier(description, prefix=["CVE", "CWE", "TEMP"]),
        )
        raw_severity = issue.get("Severity")
        severity_score = get_severity_value(raw_severity)

        # Object maps to RefinedIssue
        return purge_escape_characters(
            {
                "library_name": package_name,
                "current_version": installed_version,
                "upgrade_version": fixed_version,
                "link": issue.get("References"),
                "key_values": key_values,
                "vulnerability_code": vulnerability_code,
                "issue_name": title or vulnerability_code,
                "key": key,
                "issue_description": description,
                "reference_identifiers": reference_ids,
                "scan_severity": raw_severity,
                "severity": severity_score,
                "file_name": target,
            },
        )


def get_severity_value(level):
    severity = -1
    if level == "INFORMATION":
        severity = 0
    elif level == "LOW":
        severity = 3
    elif level == "MEDIUM":
        severity = 6
    elif level == "HIGH":
        severity = 8
    elif level == "CRITICAL":
        severity = 10

    return severity


def purge_escape_characters(issue):
    """Removes escape characters from a dictionary value

    Arguments:
        issue {dict} -- Used for RefinedIssue, describes a vulnerability

    Returns:
        {dict}
    """
    try:
        issue_copy = issue.copy()
        for key, value in issue_copy.items():

            if value is None:
                del issue[key]
            elif isinstance(value, dict):
                issue[key] = [purge_escape_characters(value)]
            elif isinstance(value, str):
                regex = re.compile(r"[\n\r\t]")
                issue[key] = regex.sub("", value).replace("\\r", "").replace("\\n", "")
            else:
                continue

        return issue
    except Exception as err:
        Exception(f"Error in Aqua Trivy purge(). Error: {err}")
