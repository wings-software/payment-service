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

import semver

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.issue_refinement.refinement.product_info import ScanTypeInfo
from gaussian.utils.text_scrapers import scrape_reference_identifier


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        config.logger.debug("Starting snyk compression")
        snyk_issues = json.loads(binary_data.decode("utf8"))
        vulnerabilities = snyk_issues.get("vulnerabilities", [])
        is_container = snyk_issues.get("docker")
        issue_type = "Container" if is_container else "Open Source"
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                vuln["issue_type"] = issue_type
        return vulnerabilities

    def normalizer(self, issue):
        issue_type = issue.get("issue_type")
        package_name = issue.get("packageName")
        package_version = issue.get("version")
        language = issue.get("language")
        package_manager = issue.get("packageManager")
        key = f"{package_name}//{package_version}"
        key_values = ["library_name", "current_version"]
        # in some cases cvssScore exists and is None
        cvss = int(issue.get("cvssScore") or -1)
        fixed_in = issue.get("fixedIn", [])
        fixed_in_version_message = "newer version"
        if fixed_in:
            if len(fixed_in) > 1:
                possible_fixed_versions = [
                    f"{package_name} v{fix}" for fix in fixed_in if semver_valid(fix)
                ]
                fixed_in_version_message = " or ".join(possible_fixed_versions)
            elif len(fixed_in) == 1 and semver_valid(fixed_in[0]):
                fixed_in_version_message = f"{package_name} v{fixed_in[0]}"
        else:
            fixed_in_version_message = "no fixed version"
        cvss_vector = issue.get("CVSSv3", "")
        description = issue.get("description", "")
        title = issue.get("title", "")
        exploit = issue.get("exploit", "")
        is_upgradable = issue.get("isUpgradable", False)
        is_patchable = issue.get("isPatchable", False)
        is_unresolved = not is_upgradable and not is_patchable
        snyk_id = issue.get("id", "")
        social_trend_alert = issue.get("socialTrendAlert", False)
        from_dependency_chain = list(issue.get("from") or [])
        upgrade_dependency_chain = list(issue.get("upgradePath") or [])
        remediation = f"No remediation available for {title}"
        if is_upgradable:
            if len(from_dependency_chain) > 2:
                logging.debug("Issue coming from indirect dependency")
                main_app = from_dependency_chain[0]
                direct_dependency = from_dependency_chain[1]
                problem_dependency = from_dependency_chain[-1]
                remediation = f"{main_app} has an issue in {problem_dependency} from direct dependency {direct_dependency}"
                upgraded_direct_dependency = get_upgraded_dependency(
                    direct_dependency, upgrade_dependency_chain
                )
                if (
                    upgraded_direct_dependency
                    and upgraded_direct_dependency != direct_dependency
                ):
                    remediation += (
                        f", try upgrading to {upgraded_direct_dependency} instead."
                    )
            elif len(from_dependency_chain) == 2:
                remediation = f"Upgrade {package_name} from v{package_version} -> {fixed_in_version_message}"
        identifiers = issue.get("identifiers", {})
        reference_identifiers = scrape_reference_identifier(
            str(identifiers),
            prefix=["CVE", "CWE", "GHSA"],
        )
        return {
            "key": key,
            "key_values": key_values,
            "library_name": package_name,
            "package_name": package_name,
            "package_version": package_version,
            "current_version": package_version,
            "package_manager": package_manager,
            "language": language,
            "introduced_through": pretty_print_dependency_path(
                from_dependency_chain,
            ),
            "upgrade_path": pretty_print_dependency_path(upgrade_dependency_chain),
            "fixed_in": fixed_in_version_message,
            "title": title,
            "exploit": exploit,
            "is_upgradable": is_upgradable,
            "is_patchable": is_patchable,
            "is_unresolved": is_unresolved,
            "known_problems": snyk_id,
            "social_trend_alert": social_trend_alert,
            "severity": cvss,
            "cvss": cvss,
            "cvss_vector": cvss_vector,
            "reference_identifiers": reference_identifiers,
            "remediation_steps": remediation,
            "issue_name": key,
            "issue_description": description,
            "issue_type": issue_type,
            "scan_type": ScanTypeInfo.SCA,
        }


def get_upgraded_dependency(dependency: str, upgrade_path: list):
    split_dependency = dependency.split("@")
    dependency_name = split_dependency[0]
    for upgrade_dep in upgrade_path:
        if upgrade_dep and dependency_name in upgrade_dep:
            return upgrade_dep
    return None


def pretty_print_dependency_path(dependency_array: list):
    if type(dependency_array) is not list:
        raise ValueError("dependency_array is not list")
    filtered_array = [dep for dep in dependency_array if dep]
    return " -> ".join(filtered_array)


def semver_valid(version):
    if version is None:
        return False
    try:
        semver.parse(version)
        return True
    except ValueError:
        return False
