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

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.issue_refinement.refinement.product_info import ScanTypeInfo
from gaussian.utils.text_scrapers import scrape_reference_identifier

from .enrichment import items as brakeman_details


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        try:
            json_data = json.loads(binary_data.decode("utf8"))
            return json_data.get("warnings", [])
        except Exception as ex:
            config.logger.error(ex)
            raise Exception(
                f"Error extracting brakeman vulnerabilities from raw issues. Error: {ex}",
            )

    def normalizer(self, issue):
        issue_type = issue.get("warning_type")
        warning_code = issue.get("warning_code")
        fingerprint = issue.get("fingerprint")
        check_name = issue.get("check_name")
        message = issue.get("message", "")
        file = issue.get("file")
        line = issue.get("line", "")
        link = issue.get("link")
        code = issue.get("code")
        render_path = issue.get("code")
        location = issue.get("location")
        user_input = issue.get("user_input")
        confidence = issue.get("confidence")
        issue_name = f"{issue_type} {warning_code}"
        reference_identifiers = scrape_reference_identifier(
            message, prefix=["CVE", "CWE", "TEMP"]
        )
        key_values = ["issue_type", "warning_code"]
        key = f"{issue_type}//{warning_code}"
        regex = ".*docs/warning_types/(.*)"
        url_types = re.findall(regex, link)
        if len(url_types) > 0:
            url_type = url_types[0].strip("/")
            if url_type.lower() in brakeman_details:
                enrichment_data = brakeman_details.get(url_type.lower(), {}).get(
                    "description", ""
                )
                message += f"\n{enrichment_data}"

        return {
            "issue_type": issue_type,
            "warning_code": warning_code,
            "fingerprint": fingerprint,
            "check_name": check_name,
            "issue_description": message,
            "file_name": file,
            "line_number": line,
            "link": link,
            "code": code,
            "render_path": render_path,
            "location": location,
            "user_input": user_input,
            "issue_name": issue_name,
            "confidence": confidence,
            "scan_type": ScanTypeInfo.SAST,
            "reference_identifiers": reference_identifiers,
            "key": key,
            "key_values": key_values,
        }
