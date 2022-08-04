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
from gaussian.utils.helper_funcs import strip_cwe_cve


def get_severity(level):
    severity = -1
    if level == "Information":
        severity = 0
    elif level == "Low":
        severity = 3
    elif level == "Medium":
        severity = 6
    elif level == "High":
        severity = 8
    elif level == "Critical":
        severity = 10

    return severity


def get_instance_severity(level):
    severity = -1
    if level == 1.0:  # information
        severity = 0
    elif level == 2.0:  # low
        severity = 3
    elif level == 3.0:  # medium
        severity = 6
    elif level == 4.0:  # high
        severity = 8
    elif level == 5.0:  # critical
        severity = 10

    return severity


def is_severity_bigger(a, b):
    return get_severity(a) > get_severity(b)


def prep_data(name, data, instance_type=str):
    if name in data and len(data[name]) > 0:
        return data[name]
    else:
        if type(instance_type) == list:
            return []
        else:
            return None


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        return json.loads(binary_data)

    def normalizer(self, issue):
        if issue.get("Issue Tool") == "Checkmarx":
            return process_checkmarx(issue)
        elif issue.get("Issue Tool") == "Snyk":
            return process_snyk(issue)

        return


def process_checkmarx(issue):
    max_scan_severity = 1.0

    cve_number = None
    cve = prep_data("CVE", issue)
    if cve:
        cve_split = cve.split("|")
        if len(cve_split) == 2:
            cve_number = cve_split[0].replace("[", "")

    cwe_number = None
    cwe = prep_data("CWE", issue)
    if cwe:
        cwe_split = cwe.split("|")
        if len(cwe_split) == 2:
            cwe_number = cwe_split[0].replace("[", "")

    description = prep_data("Description", issue)
    instances = prep_data("Instances", issue)

    issue_confidence = prep_data("Issue Confidence", issue)
    issue_name = prep_data("Issue Name", issue)

    issue_priority = prep_data("Issue Priority", issue)
    severity = prep_data("Issue Severity", issue)
    issue_tool = prep_data("Issue Tool", issue)
    jira_description = prep_data("Jira Description", issue)

    links = prep_data("Links", issue)
    overview = prep_data("Overview", issue)
    paths = prep_data("Paths", issue)

    rp_comment = prep_data("RP Comment", issue)
    rp_defect_type = prep_data("RP Defect Type", issue)
    recommendations = prep_data("Recommendations", issue)
    references = prep_data("References", issue)
    references_split = references.split("|")
    references_file = references_split[0].replace("[", "")

    repo = prep_data("Repo", issue)
    snippet = prep_data("Snippet", issue)
    steps_to_reproduce = prep_data("Steps To Reproduce", issue)
    tags = prep_data("Tags", issue, list)
    error_string = prep_data("error_string", issue)

    issue_severity = 0
    if severity is not None:
        if is_severity_bigger(severity, max_scan_severity):
            max_scan_severity = get_severity(severity)

        issue_severity = get_severity(severity)

    key = issue_name
    key_values = ["issue_name"]

    identifiers = []

    if cwe_number:
        identifiers.append({"type": "cwe", "id": strip_cwe_cve(cwe_number)})

    if cve_number:
        identifiers.append({"type": "cve", "id": strip_cwe_cve(cve_number)})

    return {
        "issue_name": issue_name,
        "issue_description": description,
        "issue_details": jira_description,
        "issue_tool": issue_tool,
        "scan_severity": max_scan_severity,
        "severity": issue_severity,
        "key": key,
        "key_values": key_values,
        "file_name": instances,
        "confidence": issue_confidence,
        "severity_code": issue_priority,
        "link": links,
        "overview": overview,
        "paths": paths,
        "product": issue_tool,
        "rp_comment": rp_comment,
        "rp_defect_type": rp_defect_type,
        "recommendation": recommendations,
        "reapsaw_reference": references_file,
        "reference_identifiers": identifiers,
        "code": snippet,
        "repo": repo,
        "steps_to_reproduce": steps_to_reproduce,
        "tags": tags,
        "error_string": error_string,
    }


def process_snyk(issue):
    max_scan_severity = 1.0

    cve = prep_data("CVE", issue)
    cwe = prep_data("CWE", issue)
    description = prep_data("Description", issue)
    instances = prep_data("Instances", issue)

    issue_confidence = prep_data("Issue Confidence", issue)
    issue_name = prep_data("Issue Name", issue)

    issue_priority = prep_data("Issue Priority", issue)
    severity = prep_data("Issue Severity", issue)
    issue_tool = prep_data("Issue Tool", issue)
    jira_description = prep_data("Jira Description", issue)

    links = prep_data("Links", issue)
    overview = prep_data("Overview", issue)
    paths = prep_data("Paths", issue)

    paths_cleanedup = None
    if paths:
        paths_cleanedup = paths.split(":")[-1]

    rp_comment = prep_data("RP Comment", issue)
    rp_defect_type = prep_data("RP Defect Type", issue)
    recommendations = prep_data("Recommendations", issue)
    references = prep_data("References", issue, list)
    references_split = references.split("\n")
    repo = prep_data("Repo", issue)
    snippet = prep_data("Snippet", issue)
    steps_to_reproduce = prep_data("Steps To Reproduce", issue)
    tags = prep_data("Tags", issue, list)
    error_string = prep_data("error_string", issue)

    language = prep_data("language", issue)
    top_level_module = prep_data("top_level_module", issue)
    upgrades = prep_data("upgrades", issue, list)

    issue_severity = 0
    if severity is not None:
        if is_severity_bigger(severity, max_scan_severity):
            max_scan_severity = get_severity(severity)

        issue_severity = get_severity(severity)

    key = paths_cleanedup
    key_values = ["paths_cleanedup"]

    identifiers = []

    if cwe:
        identifiers.append({"type": "cwe", "id": strip_cwe_cve(cwe)})

    if cve:
        identifiers.append({"type": "cve", "id": strip_cwe_cve(cve)})

    return {
        "issue_name": issue_name,
        "issue_description": description,
        "issue_details": jira_description,
        "issue_tool": issue_tool,
        "scan_severity": max_scan_severity,
        "severity": issue_severity,
        "key": key,
        "paths_cleanedup": paths_cleanedup,
        "key_values": key_values,
        "file_name": instances,
        "confidence": issue_confidence,
        "severity_code": issue_priority,
        "link": links,
        "overview": overview,
        "paths": paths,
        "product": issue_tool,
        "rp_comment": rp_comment,
        "rp_defect_type": rp_defect_type,
        "recommendation": recommendations,
        "reapsaw_reference": references_split,
        "reference_identifiers": identifiers,
        "code": snippet,
        "repo": repo,
        "steps_to_reproduce": steps_to_reproduce,
        "tags": tags,
        "error_string": error_string,
        "language": language,
        "top_level_module": top_level_module,
        "upgrades": upgrades,
    }
