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
from gaussian.utils.text_scrapers import scrape_reference_identifier


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        try:
            json_data = json.loads(binary_data.decode("utf8"))
            raw_bandit_issues = json_data.get("results", [])
            return raw_bandit_issues
        except Exception as ex:
            config.logger.error(ex)
            raise Exception(
                f"Error extracting bandit vulnerabilities from raw issues. Error: {ex}",
            )

    def normalizer(self, issue):
        code = issue.get("code")
        file_name = issue.get("filename")
        confidence = issue.get("issue_confidence")
        issue_severity = str(issue.get("issue_severity", ""))
        severity = scan_severities[issue_severity]
        issue_text = issue.get("issue_text")
        line_number = issue.get("line_number")
        line_range = issue.get("line_range")
        test_id = issue.get("test_id")
        test_name = issue.get("test_name")
        reference_identifiers = scrape_reference_identifier(
            issue_text, prefix=["CVE", "CWE", "TEMP"]
        )
        key_values = ["test_id", "test_name"]
        key = f"{test_id}//{test_name}"

        return {
            "code": code,
            "file_name": file_name,
            "confidence": confidence,
            "severity": severity,
            "scan_severity": issue_severity,
            "issue_text": issue_text,
            "issue_description": issue_text,
            "line_number": line_number,
            "line_range": line_range,
            "test_id": test_id,
            "test_name": test_name,
            "issue_name": test_name,
            "reference_identifiers": reference_identifiers,
            "scan_type": ScanTypeInfo.SAST,
            "key": key,
            "key_values": key_values,
        }


scan_severities = {
    "LOW": 3.9,
    "MEDIUM": 6.9,
    "HIGH": 10.0,
}
