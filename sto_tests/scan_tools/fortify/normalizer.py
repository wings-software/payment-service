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

import xmltodict

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC


class FortifyReport(object):
    RESULTS_OUTLINE = "Results Outline"
    VULNERABILITIES = "vulnerabil.*by.*"
    ABSTRACT = "Abstract"


def pretty_print_fvdl_reference(reference: dict):
    pretty_string = ""
    for key, value in reference.items():
        pretty_string += f"{key}: {value}\t"
    return pretty_string


def get_severity(level):
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
        self.isXMLData = False
        self.isJSONData = False
        self.isFVDLata = False

    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        try:
            try:
                a = xmltodict.parse(binary_data.decode("utf-8"))
                self.isXMLData = True
            except Exception:
                try:
                    a = json.loads(binary_data.decode("utf-8"))
                    self.isJSONData = True
                except Exception as ex:
                    config.logger.error(
                        "Error reading file, only support JSON and XML uploads"
                    )
                    config.logger.error(ex)
                    raise

            data = json.loads(json.dumps(a))

            if "FVDL" in data and "@version" in data["FVDL"]:
                self.descriptions = {}
                # convert the list of descriptions to a dictionary for faster lookup
                fvdl_descriptions = data["FVDL"]["Description"]
                for item in fvdl_descriptions:
                    self.descriptions[item.get("@classID")] = item
                self.isFVDLata = True
                issues = data["FVDL"]["Vulnerabilities"]["Vulnerability"]
                if not isinstance(issues, list):
                    issues = [issues]
                return issues
            elif self.isJSONData and not self.isXMLData:
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    return data.get("data")
                else:
                    raise TypeError
        except Exception as ex:
            config.logger.error(ex)
            raise

    def normalizer(self, issue):
        if self.isFVDLata:
            return self.extract_fvdl_data(issue)
        else:
            return self.extract_json_data(issue)

    def extract_fvdl_data(self, issue):
        analysisInfo = issue["AnalysisInfo"]["Unified"]["Context"]
        classInfo = issue["ClassInfo"]
        instanceInfo = issue["InstanceInfo"]
        namespace = None
        functionName = None
        functionEnclosingClass = None
        namespace = None
        functionName = None
        functionEnclosingClass = None
        sourcePath = None
        sourceColumnEnd = None
        sourceColumnStart = None
        sourceLineStart = None
        sourceLineEnd = None
        if analysisInfo is not None:
            if "Function" in analysisInfo:
                if "@namespace" in analysisInfo["Function"]:
                    namespace = analysisInfo["Function"]["@namespace"]

            if "Function" in analysisInfo:
                if "@name" in analysisInfo["Function"]:

                    functionName = analysisInfo["Function"]["@name"]

            if "Function" in analysisInfo:
                if "@enclosingClass" in analysisInfo["Function"]:

                    functionEnclosingClass = analysisInfo["Function"]["@enclosingClass"]

            if "FunctionDeclarationSourceLocation" in analysisInfo:
                if "@path" in analysisInfo["FunctionDeclarationSourceLocation"]:

                    sourcePath = analysisInfo["FunctionDeclarationSourceLocation"][
                        "@path"
                    ]

                if "@colEnd" in analysisInfo["FunctionDeclarationSourceLocation"]:

                    sourceColumnEnd = analysisInfo["FunctionDeclarationSourceLocation"][
                        "@colEnd"
                    ]

                if "@colStart" in analysisInfo["FunctionDeclarationSourceLocation"]:

                    sourceColumnStart = analysisInfo[
                        "FunctionDeclarationSourceLocation"
                    ]["@colStart"]

                if "@line" in analysisInfo["FunctionDeclarationSourceLocation"]:

                    sourceLineStart = analysisInfo["FunctionDeclarationSourceLocation"][
                        "@line"
                    ]

                if "@lineEnd" in analysisInfo["FunctionDeclarationSourceLocation"]:

                    sourceLineEnd = analysisInfo["FunctionDeclarationSourceLocation"][
                        "@lineEnd"
                    ]

        classId = classInfo["ClassID"]
        descriptionInfo = self.descriptions[classId]

        analyzerName = classInfo["AnalyzerName"]
        kingdom = classInfo["Kingdom"]

        key = kingdom
        key_values = ["kingdom"]
        issue_name = ""
        class_type = None
        if "Type" in classInfo:
            class_type = classInfo["Type"]
            key += f"//{class_type}"
            issue_name += f"{class_type} "
            key_values.append("class_type")
        sub_type = None
        if "Subtype" in classInfo:
            sub_type = classInfo["Subtype"]
            key += f"//{sub_type}"
            issue_name += f"{sub_type} "
            key_values.append("sub_type")

        instanceConfidence = instanceInfo["Confidence"]

        instanceSeverity = float(instanceInfo["InstanceSeverity"])

        issue_description = descriptionInfo["Explanation"]

        tips = [descriptionInfo.get("Tips", {}).get("Tip", [])]

        references = None
        nested_references = descriptionInfo.get("References", {}).get(
            "Reference",
            [],
        )
        # This is corner case that only happens when there is a single
        # reference this path is an object and not an array of objects
        if isinstance(nested_references, dict):
            references = [pretty_print_fvdl_reference(nested_references)]
        elif isinstance(nested_references, list):
            references = [
                pretty_print_fvdl_reference(reference)
                for reference in nested_references
            ]

        new_issue = {
            "issue_name": issue_name,
            "issue_description": issue_description,
            "issue_details": descriptionInfo["Explanation"],
            "severity": instanceSeverity,
            "key": key,
            "key_values": key_values,
            "namespace": namespace,
            "library_name": functionName,
            "function_enclosing_class": functionEnclosingClass,
            "file_name": sourcePath,
            "source_column_end": sourceColumnEnd,
            "source_column_start": sourceColumnStart,
            "line_number": sourceLineStart,
            "sourceLineEnd": sourceLineEnd,
            "analyzer": analyzerName,
            "kingdom": kingdom,
            "class_type": class_type,
            "sub_type": sub_type,
            "confidence": instanceConfidence,
            "abstract": descriptionInfo["Abstract"],
            "recommendations": descriptionInfo["Recommendations"],
            "references": references,
            "remediation_steps": tips,
        }
        # keep the raw issues
        for key in issue:
            if key.startswith("_raw_"):
                new_issue[key] = issue[key]
        return new_issue

    def extract_json_data(self, issue):
        # handle case for customer suppressing issues
        if issue.get("suppressed") or issue.get("removed") or issue.get("hidden"):
            return
        class_type = issue.get("classType")
        sub_type = issue.get("subType")
        kingdom = issue.get("kingdom")
        issue_name = issue.get("issueName")
        # classType and subType are not present in json body split issue name and set values
        if class_type is None and sub_type is None:
            split_issue_name = issue_name.split(":")
            if len(split_issue_name) == 1:
                class_type = split_issue_name[0].strip()
                key = f"{kingdom}//{class_type}"
                key_values = ["kingdom", "class_type"]
            elif len(split_issue_name) == 2:
                class_type = split_issue_name[0].strip()
                sub_type = split_issue_name[1].strip()
                key = f"{kingdom}//{class_type}//{sub_type}"
                key_values = ["kingdom", "class_type", "sub_type"]
            else:
                key = f"{kingdom}"
                key_values = ["kingdom"]

        issue_name_pretty = ""
        if class_type is not None:
            issue_name_pretty += class_type
        if sub_type is not None:
            issue_name_pretty += f"_{sub_type}"

        issue_severity = float(issue.get("severity"))

        issue_details = issue.get("issueDetails")
        issue_data_detail = None
        issue_data_abstract = None
        issue_data_tips = None
        issue_data_references = None
        issue_data_recommendations = None
        tips = []
        references = []
        if issue_details is not None and issue_details.get("data") is not None:
            issue_data = issue_details.get("data")
            # Issue details data is nested down 1 layer
            issue_data_detail = issue_data.get("detail")
            issue_data_abstract = issue_data.get("brief")
            issue_data_tips = issue_data.get("tips")
            if issue_data_tips and isinstance(issue_data_tips, str):
                tips = issue_data_tips.split("\n\n")
            issue_data_references = issue_data.get("references")
            if issue_data_references and isinstance(issue_data_references, str):
                references = issue_data_references.split("\n\n")
            issue_data_recommendations = issue_data.get("recommendation")

        # convert raw json paramaters to refined_issue casing
        # when available add new fields for description and details from api body
        new_issue = {
            "project_version_id": issue.get("projectVersionId"),
            "scan_id": issue.get("lastScanId"),
            "project_version_name": issue.get("projectVersionName"),
            "project": issue.get("projectName"),
            "revision": issue.get("revision"),
            "folder_id": issue.get("folderId"),
            "folder_guid": issue.get("folderGuid"),
            "issue_name": issue_name_pretty,
            "analyzer": issue.get("analyzer"),
            "kingdom": kingdom,
            "class_type": class_type,
            "sub_type": sub_type,
            "friority": issue.get("friority"),
            "reviewed": issue.get("reviewed"),
            "url": issue.get("bugUrl"),
            "external_bug_id": issue.get("externalBugId"),
            "primary_tag": issue.get("primaryTag"),
            "has_attachments": issue.get("hasAttachments"),
            "has_correlated_issues": issue.get("hasCorrelatedIssues"),
            "scan_status": issue.get("scanStatus"),
            "found_date": issue.get("foundDate"),
            "removed_date": issue.get("removedDate"),
            "scan_type": issue.get("engineType"),
            "display_engine_type": issue.get("displayEngineType"),
            "issue_type": issue.get("engineCategory"),
            "primary_rule_guid": issue.get("primaryRuleGuid"),
            "impact_score": issue.get("impact"),
            "likelihood": issue.get("likelihood"),
            "severity": issue_severity,
            "confidence": issue.get("confidence"),
            "audited": issue.get("audited"),
            "issue_status": issue.get("issueStatus"),
            "primary_tag_value_auto_applied": issue.get("primaryTagValueAutoApplied"),
            "hasComments": issue.get("hasComments"),
            "removed": issue.get("removed"),
            "suppressed": issue.get("suppressed"),
            "hidden": issue.get("hidden"),
            "key": key,
            "key_values": key_values,
            "file_name": issue.get("primaryLocation"),
            "full_file_name": issue.get("fullFileName"),
            "line_number": issue.get("lineNumber"),
            "_href": issue.get("_href"),
            "issue_instance_id": issue.get("issueInstanceId"),
            "issue_description": issue_data_detail,
            "abstract": issue_data_abstract,
            "recommendations": issue_data_recommendations,
            "references": references,
            "remediation_steps": tips,
        }
        return new_issue
