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

import dateutil.parser
import xmltodict

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.utils.helper_funcs import is_vuln_false_positive, timestamp_microsecond


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        issues = []
        extra_data = {}
        try:
            a = xmltodict.parse(binary_data.decode("utf-8"))
            data = json.loads(json.dumps(a))

            cxXMLResults = data.get("CxXMLResults", None)
            result = {"issues": issues, "extra_data": extra_data}

            if cxXMLResults is None:
                raise Exception(
                    "CxXMLResults is not contained within the checkmarx output"
                )

            checkmarx_issues = cxXMLResults.get("Query", [])
            extra_data["filesScanned"] = cxXMLResults.get("@FilesScanned", None)
            extra_data["linesScanned"] = cxXMLResults.get("@LinesOfCodeScanned", None)

            try:
                scan_date = cxXMLResults.get("@ScanStart")
                job_runtime = timestamp_microsecond(dateutil.parser.parse(scan_date))
                result["job_runtime"] = job_runtime
                extra_data["toolData"] = {"lastScanTime": job_runtime}
            except Exception as e:
                config.logger.info(
                    f"Cannot parse scan submission date: {e}", exc_info=True
                )

            vulnerability_counts = {}
            extra_data["underlyingVulnerabilityCounts"] = vulnerability_counts

            if not isinstance(checkmarx_issues, list):
                checkmarx_issues = [checkmarx_issues]

            return checkmarx_issues
        except Exception as ex:
            config.logger.error(ex)
            raise

    def normalizer(self, issue):
        if "Result" not in issue:
            return

        name = issue.get("@name")
        scan_severity = issue.get("@Severity")

        if scan_severity == "Information":
            severity = 0
        elif scan_severity == "Low":
            severity = 3
        elif scan_severity == "Medium":
            severity = 6
        elif scan_severity == "High":
            severity = 8
        elif scan_severity == "Critical":
            severity = 10
        else:
            logging.info(
                f"Checkmarx - Unknown Severity Level: {scan_severity}",
            )
            severity = -1

        cwe = issue.get("@cweId", None)
        if cwe:
            identifiers = [{"type": "cwe", "id": cwe}]
        else:
            identifiers = []
        issue_description = issue.get("@categories")
        if not issue_description:
            issue_description = name
        issue_name = name
        group = issue.get("@group", None)
        if group:
            issue_name = f"{issue_name}: {group}"

        key = f"{name}//{group}"
        key_values = ["name", "group"]
        vuln_details = []

        line_items = issue["Result"]
        if not isinstance(line_items, list):
            line_items = [line_items]
        issue_vulnerability_counts = {}

        for vuln in line_items:
            issue_is_false_positive = is_vuln_false_positive(vuln)
            if issue_is_false_positive:
                continue

            filename = vuln.get("@FileName")
            line = vuln.get("@Line")
            vulnseverity = vuln.get("@Severity")
            unique_vulnerability_value = f"{filename}{line}"

            if vulnseverity not in issue_vulnerability_counts:
                issue_vulnerability_counts[vulnseverity] = set()

            issue_vulnerability_counts[vulnseverity].add(unique_vulnerability_value)
            link = vuln.get("@DeepLink")
            details = vuln.get("Path", {}).get("PathNode", [])

            if not isinstance(details, list):
                details = [details]

            snippets = {}
            for detail in details:
                code_lines = detail.get("Snippet", {}).get("Line", {})
                line = code_lines.get("Number", None)
                snippet = code_lines.get("Code", None)

                if snippet not in snippets:
                    snippets[snippet] = set()

                snippets[snippet].add(line)

            snippet_data = []

            for snippet, value in snippets.items():
                snippet_data.append({"snippet": snippet, "lines": list(value)})

            vuln_details.append(
                {
                    "filename": filename,
                    "severity": vulnseverity,
                    "link": link,
                    "snippets": snippet_data,
                },
            )

        if len(vuln_details) == 0:
            # if vuln details is empty, all instances of the issue are false positives
            return

        return {
            "issue_name": issue_name,
            "name": name,
            "issue_description": issue_description,
            "scan_severity": scan_severity,
            "severity": severity,
            "reference_identifiers": identifiers,
            "key": key,
            "key_values": key_values,
            "vulnerability_details": vuln_details,
            "group": group,
            "cwe": cwe,
        }
