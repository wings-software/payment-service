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

import dateutil.parser

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.utils.helper_funcs import get_severity_code, timestamp_microsecond
from gaussian.utils.text_scrapers import scrape_reference_identifier


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        issues = []
        extra_data = {}

        try:
            jsonString = binary_data.decode("utf8").replace("'", '"')
            data = json.loads(jsonString)
        except Exception:
            data = json.loads(binary_data.decode("utf8"))

        sl_response = data.get("response", data)
        sl_scan = sl_response.get("scan", None)
        sl_findings = sl_response.get("findings", None)

        if sl_scan is None:
            raise Exception("sl_scan is not contained within the shiftleft output")
        if sl_findings is None:
            raise Exception("sl_findings is not contained within the shiftleft output")

        extra_data["scanName"] = sl_scan.get("app", None)
        extra_data["scanId"] = sl_scan.get("id", None)
        extra_data["successful"] = sl_scan.get("successful", None)

        try:
            scan_date = sl_scan.get("started_at")
            job_runtime = timestamp_microsecond(dateutil.parser.parse(scan_date))
            extra_data["toolData"] = {
                "lastScanTime": job_runtime,
                "language": sl_scan.get("language", None),
                "version": sl_scan.get("version", None),
                "numberOfExpressions": sl_scan.get("number_of_expressions", None),
                "internalId": sl_scan.get("internal_id", None),
            }
        except Exception as e:
            config.logger.info(f"Cannot parse scan submission date: {e}", exc_info=True)

        if sl_findings:
            for finding in sl_findings:
                file_locations = finding.get("details", {}).get("file_locations")
                if file_locations and len(file_locations) > 0:
                    # TODO
                    # issue has multiple file locations, strip them out and append them to the list
                    for file_location in file_locations:
                        finding_to_append = copy.deepcopy(finding)
                        finding_to_append["details"][
                            "lineNumber"
                        ] = file_location.split(":")[1]
                        finding_to_append["details"]["fileName"] = file_location.split(
                            ":"
                        )[0]
                        finding_to_append["details"]["file_locations"] = []
                        issues.append(finding_to_append)
                else:
                    issues.append(finding)

        return {"issues": issues, "extra_data": extra_data}

    def normalizer(self, issue):
        issue_category = issue.get("category", None)
        issue_type = issue.get("type", None)
        issue_title = issue.get("title", None)
        tool_severity = issue.get("severity", "").lower()
        key_values = []
        delimiter = ""
        if issue_type == "vuln":
            # issue is a vuln, use true severity and category as key
            key = (issue_category).replace(" ", "_").lower()
            issue_severity = issue.get("severity", "").lower()
            key_values = ["issue_category"]
        else:
            # issue is insight, set severity to info and use title as info
            key = (issue_title).replace(" ", "_").lower()
            issue_severity = "info"
            key_values = ["issue_name"]

        issue_id = issue.get("id", None)
        issue_description = issue.get("description", None)
        issue_internal_id = issue.get("internal_id", None)
        owasp_category = issue.get("owasp_category", None)
        scan_first_seen = issue.get("scan_first_seen", None)
        version_first_seen = issue.get("version_first_seen", None)
        details = issue.get("details", {})
        lineNumber = (str(details.get("lineNumber", "")),)
        fileName = (str(details.get("fileName", "")),)
        created_at = issue.get("created_at")
        issue_created_at = timestamp_microsecond(dateutil.parser.parse(created_at))

        if issue_severity == "info":
            severity = 0
        elif issue_severity == "moderate":
            severity = 6
        elif issue_severity == "critical":
            severity = 10
        else:
            logging.warn(
                f"shiftleft - Unknown Severity Level: {issue_severity}",
            )
            severity = -1

        tags = issue.get("tags")
        issue_tags = []

        reference_identifiers = []
        new_identifiers = scrape_reference_identifier(
            issue_description,
            prefix=["CVE", "CWE", "OWASP"],
        )
        reference_identifiers = [
            x for x in new_identifiers if x not in reference_identifiers
        ]

        if isinstance(tags, list):
            for tag in tags:
                issue_tags.append(
                    {
                        tag["key"]: tag["value"],
                    },
                )
        elif isinstance(tags, dict):
            issue_tags.append(tags)
        else:
            logging.error("Tags must either be list or dict")

        return {
            "issue_id": issue_id,
            "key": key,
            "key_values": key_values,
            "delimiter": delimiter,
            "issue_type": issue_type,
            "issue_name": issue_title,
            "line_number": lineNumber,
            "file_name": fileName,
            "link": details.get("Link", ""),
            "sink_method": details.get("sink_method", ""),
            "source_method": details.get("source_method", ""),
            "data_element": details.get("DATA_ELEMENT", ""),
            "issue_description": issue_description,
            "issue_internal_id": issue_internal_id,
            "owasp_category": owasp_category,
            "issue_category": issue_category,
            "scan_first_seen": scan_first_seen,
            "version_first_seen": version_first_seen,
            "issue_severity": issue_severity,
            "scan_severity": tool_severity,
            "severity": severity,
            "severity_code": get_severity_code(severity),
            "created_at": issue_created_at,
            "reference_identifiers": reference_identifiers,
            "shiftleft_tags": issue_tags,
        }
