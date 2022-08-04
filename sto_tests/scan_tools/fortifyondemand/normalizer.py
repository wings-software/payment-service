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
from gaussian.utils.helper_funcs import strip_cwe_cve


def get_severity(level):
    if level == "Info":
        return 0
    if level == "Information":
        return 0
    elif level == "Low":
        return 3
    elif level == "Medium":
        return 6
    elif level == "High":
        return 8
    elif level == "Critical":
        return 10
    else:
        return -1


def get_instance_severity(level):
    if level == 1.0:  # information
        return 0
    elif level == 2.0:  # low
        return 3
    elif level == 3.0:  # medium
        return 6
    elif level == 4.0:  # high
        return 8
    elif level == 5.0:  # critical
        return 10
    else:
        return -1


def is_severity_bigger(a, b, severity_type="instance"):
    if severity_type == "instance":
        return get_instance_severity(a) > get_instance_severity(b)
    else:
        return get_severity(a) > get_severity(b)


class Refiner(RefinerABC):
    def __init__(self):
        self.as_supplemental = False
        self.policy_data = {}

    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        data = json.loads(binary_data)
        scanVulns = []

        if not policy_data:
            policy_data = self.policy_data
        self.policy_data = policy_data

        targetScanType = policy_data.get("permanentRunOptions", {}).get(
            "fortifyOnDemandScanTypeOption", None
        )
        if not targetScanType:
            config.logger.warning(
                "unspecified scanType, selecting a type based on envType"
            )
            envType = policy_data.get("environmentType", None)
            if (
                envType == "artifact"
                or envType == "github"
                or envType == "docker"
                or envType == "bitbucket"
            ):
                targetScanType = "Static"
            elif envType == "custom" or envType == "direct":
                targetScanType = "Dynamic"
            else:
                raise Exception(
                    "Policy enviornment type is not one of the following: artifact, repository, docker, custom, direct."
                )

        for s in dict(sorted(data.items(), key=lambda x: int(x[0]), reverse=True)):
            # this is filter to grab the most recent scanId
            scanType = data[s].get("scanData", "{}").get("scanType", None)
            if scanType not in ["Static", "Dynamic", "OpenSource"]:
                config.logger.warning(f"unhandled scanType ({scanType}) found")

            if scanType == targetScanType:
                return data[s].get("vulnerability_data", None)

    def normalizer(self, issue):
        max_scan_severity = 1.0
        lineNumber = None
        primaryLocation = None
        primaryLocationFull = None
        summarySeverity = None
        assignedUser = None
        developerStatus = None
        auditorStatus = None
        bugSubmitted = None
        bugLink = None
        vulnId = None
        releaseId = None
        url = None

        if "summary" in issue:
            if "lineNumber" in issue["summary"]:
                lineNumber = issue["summary"]["lineNumber"]
            if "primaryLocation" in issue["summary"]:
                primaryLocation = issue["summary"]["primaryLocation"]
            if "primaryLocationFull" in issue["summary"]:
                primaryLocationFull = issue["summary"]["primaryLocationFull"]
                url = issue["summary"]["primaryLocationFull"]
            if "severity" in issue["summary"]:
                summarySeverity = issue["summary"]["severity"]
                supplementalSeverityFilter = ["Best Practice"]
                if (
                    summarySeverity in supplementalSeverityFilter
                    and not self.as_supplemental
                ):
                    if is_severity_bigger(
                        summarySeverity, max_scan_severity, "notinstance"
                    ):
                        max_scan_severity = summarySeverity
                elif (
                    summarySeverity not in supplementalSeverityFilter
                    and self.as_supplemental
                ):
                    if is_severity_bigger(
                        summarySeverity, max_scan_severity, "notinstance"
                    ):
                        max_scan_severity = summarySeverity
                else:
                    return

            if "assignedUser" in issue["summary"]:
                assignedUser = issue["summary"]["assignedUser"]
            if "developerStatus" in issue["summary"]:
                developerStatus = issue["summary"]["developerStatus"]
            if "auditorStatus" in issue["summary"]:
                auditorStatus = issue["summary"]["auditorStatus"]
            if "notes" in issue["summary"]:
                bugSubmitted = issue["summary"]["bugSubmitted"]
            if "notes" in issue["summary"]:
                bugLink = issue["summary"]["bugLink"]
            if "notes" in issue["summary"]:
                vulnId = issue["summary"]["vulnId"]
            if "notes" in issue["summary"]:
                releaseId = issue["summary"]["releaseId"]

        isStaticDetails = None
        summary = None
        explanation = None
        ruleId = None
        impact = None
        probability = None
        raw_severity = None
        confidence = None
        analyzerName = None
        source = None
        sink = None

        if "details" in issue:
            if "isStatic" in issue["details"]:
                isStaticDetails = issue["details"]["isStatic"]
            if "summary" in issue["details"]:
                summary = issue["details"]["summary"]
            if "explanation" in issue["details"]:
                explanation = issue["details"]["explanation"]
            if "ruleId" in issue["details"]:
                ruleId = issue["details"]["ruleId"]
            if "impact" in issue["details"]:
                impact = issue["details"]["impact"]
            if "probability" in issue["details"]:
                probability = issue["details"]["probability"]
            if "severity" in issue["details"]:
                raw_severity = issue["details"]["severity"]
            if "confidence" in issue["details"]:
                confidence = issue["details"]["confidence"]
            if "analyzerName" in issue["details"]:
                analyzerName = issue["details"]["analyzerName"]
            if "source" in issue["details"]:
                source = issue["details"]["source"]
            if "sink" in issue["details"]:
                sink = issue["details"]["sink"]

            complianceCategories = None
            comp_cats = None
            if "complianceCategories" in issue["details"]:
                complianceCategories = issue["details"]["complianceCategories"]
                comp_cats = []
                for comp_cat in complianceCategories:
                    cat = {}
                    if "categoryName" in comp_cat:
                        cat["categoryName"] = comp_cat["categoryName"]
                    if "complianceItems" in comp_cat:
                        comp_items = []
                        for comp_issue in comp_cat["complianceItems"]:
                            comp_items.append(comp_issue["complianceRule"])

                        cat["compliance_items"] = comp_items

                    comp_cats.append(cat)

        category = None
        if "category" in issue:
            category = issue["category"]

        recommendations = None
        tips = None
        references = None

        if "recommendations" in issue:
            if "recommendations" in issue["recommendations"]:
                recommendations = issue["recommendations"]["recommendations"]
            if "tips" in issue["recommendations"]:
                tips = issue["recommendations"]["tips"]
            if "references" in issue["recommendations"]:
                references = issue["recommendations"]["references"]

        traceEntries = None

        if "traces" in issue and issue.get("traces", {}) is not None:
            if "traceEntries" in issue["traces"]:

                traceEntries = issue["traces"]["traceEntries"]

        issue_name_parts = []
        if source:
            issue_name_parts.append(source)
        if sink:
            issue_name_parts.append(sink)

        issue_name_source = primaryLocation

        # The assumption is that details.isStatic allows to differentiate
        # between static and dynamic scans
        if isStaticDetails:
            issue_name_source = primaryLocationFull
            if lineNumber is not None:
                issue_name_source = f"{issue_name_source}"

        name_parts = issue_name_source.split("?")

        # The assumption is that single question mark represets correct url
        # and we'd like to strip out query parameters out of issue name
        if len(name_parts) == 2:
            issue_name_parts.append(name_parts[0])

            summary = issue_name_source + "\n\n" + summary
        else:
            issue_name_parts.append(issue_name_source)

        issue_name = "_".join(issue_name_parts)
        if category:
            issue_name = f"{category} - ({ruleId})"
            key = f"{category}//{ruleId}"
            key_values = ["category", "ruleId"]
        else:
            key = f"{ruleId}"
            key_values = ["ruleId"]

        reference_identifiers = []
        for cc in complianceCategories:
            if ("categoryName" in cc and "complianceItems" in cc) and cc[
                "categoryName"
            ].lower() in ["cwe", "cve"]:
                for cr in cc["complianceItems"]:
                    if "complianceRule" in cr:
                        bundle = {
                            "type": cc["categoryName"].lower(),
                            "id": strip_cwe_cve(cr["complianceRule"]),
                        }
                        reference_identifiers.append(bundle)

        issue_severity = 0
        issue_max_severity = 0
        if summarySeverity:
            issue_severity = get_severity(summarySeverity)
            if issue_severity == -1:
                logging.warning(
                    f"couldn't find severity mapping: {summarySeverity} ",
                )
            issue_max_severity = get_severity(max_scan_severity)
        else:
            logging.warning(f"issue refining issue {issue_severity} ")

        return {
            "issue_name": issue_name,
            "issue_description": summary,
            "issue_details": explanation,
            "scan_severity": float(issue_max_severity),
            "severity": float(issue_severity),
            "raw_severity": raw_severity,
            "key": key,
            "key_values": key_values,
            "line_number": lineNumber,
            "analyzer_name": analyzerName,
            "confidence": confidence,
            "recommendations": recommendations,
            "references": references,
            "remediation_steps": tips,
            "auditor_status": auditorStatus,
            "assigned_user": assignedUser,
            "primaryLocationFull": primaryLocationFull,
            "developerStatus": developerStatus,
            "bugSubmitted": bugSubmitted,
            "bugLink": bugLink,
            "vulnId": vulnId,
            "releaseId": releaseId,
            "impact": impact,
            "probability": probability,
            "reference_identifiers": reference_identifiers,
            "compliance_categories": complianceCategories,
            "traces": traceEntries,
            "url": url,
            "category": category,
            "rule_id": ruleId,
        }

    def supplemental_data(self, config, binary_data, target=None):
        self.as_supplemental = True
        return self.raw_issue_extractor(config, binary_data)
