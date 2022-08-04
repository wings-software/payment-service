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
from base64 import b64decode

import humanfriendly
import xmltodict

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.issue_refinement.refinement.product_info import ScanTypeInfo


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        try:
            data = json.loads(json.dumps(xmltodict.parse(binary_data.decode("utf-8"))))

            if "issues" not in data:
                return []

            vulnerabilities = data["issues"].get("issue", [])

            # if we have only one issue, add it to list for processing
            if isinstance(vulnerabilities, dict):
                vulnerabilities = [vulnerabilities]

            return vulnerabilities
        except Exception as ex:
            config.logger.error(ex)
            raise

    def normalizer(self, issue):
        if isinstance(issue, str):
            return
        issue_name = issue.get("name", "")
        issue_description = issue.get("issueBackground", None)
        if not issue_description:
            issue_description = issue_name
        elif isinstance(issue_description, str):
            issue_description = issue_description.strip()
        issue_detail = issue.get("issueDetail", "")
        target = issue.get("host", {})
        ip = target.get("@ip", "")
        host = target.get("#text", "")

        request_response = issue.get("requestresponse", {})
        if isinstance(request_response, dict):
            requests = [process_request_response(request_response)]
        elif isinstance(request_response, list):
            requests = []
            for rr in request_response:
                request_object = process_request_response(rr)
                if request_object not in requests:
                    # filter out duplicates
                    requests.append(request_object)
        else:
            requests = []
        # remove empty values
        requests = [
            request
            for request in requests
            if (request.get("request") != "" or request.get("response") != "")
        ]

        try:
            if len(str(requests)) > 20000:
                logging.warning("requests is too large, redacting the results")
                # limit the request size object, to avoid the issues-api throwing
                # ('Connection aborted.', ConnectionResetError(104, 'Connection reset by peer')
                requests = [
                    {
                        "message": "The request and response data was too large. Please see the attached PDF report for more details.",
                    },
                ]
        except Exception:
            requests = [
                {"message": "Please see the attached PDF report for more details."},
            ]

        scan_severity = issue.get("severity", "")

        remediation_steps = issue.get("remediationBackground", None)
        if not remediation_steps:
            remediation_steps = issue.get("remediationDetail", None)
        if isinstance(remediation_steps, str):
            remediation_steps = remediation_steps.strip()

        confidence = issue.get("confidence", "")
        references = issue.get("references", "")
        path = issue.get("path", "")
        vulnerability_classification = issue.get(
            "vulnerabilityClassifications",
            "",
        )

        if scan_severity == "Information":
            severity = 0
        elif scan_severity == "Low":
            severity = 3
        elif scan_severity == "Medium":
            severity = 6
        elif scan_severity == "High":
            severity = 10
        else:
            logging.info(f"Burp - Unknown Severity Level: {scan_severity}")
            severity = -1

        cwes = re.findall("CWE-([0-9]*)", vulnerability_classification)
        identifiers = [{"type": "cwe", "id": cwe_id} for cwe_id in cwes]
        key = f"{issue_name}"
        key_values = ["issue_name"]

        return {
            "issue_name": issue_name,
            "scan_type": ScanTypeInfo.DAST,
            "issue_description": issue_description,
            "issue_detail": issue_detail,
            "host": host,
            "ip": ip,
            "requests": requests,
            "severity": severity,
            "scan_severity": scan_severity,
            "confidence": confidence,
            "file_name": path,
            "link": references,
            "remediation_steps": remediation_steps,
            "reference_identifiers": identifiers,
            "key": key,
            "key_values": key_values,
            "cwes": cwes,
        }


def process_request_response(rr):
    rr_size_limit = 16384  # 16Kb

    try:
        request_bytes = b64decode(rr.get("request", {}).get("#text", ""))
        request = (
            request_bytes.decode("utf8")
            if len(request_bytes) < rr_size_limit
            else (
                f"Size of the request is "
                f"{humanfriendly.format_size(len(request_bytes), binary=True)}. "
                f"See the attached burp report for details."
            )
        )
    except UnicodeDecodeError:
        request = "Could not decode request as text."

    try:
        response_bytes = b64decode(rr.get("response", {}).get("#text", ""))
        response = (
            response_bytes.decode("utf8")
            if len(response_bytes) < rr_size_limit
            else (
                f"Size of the response is "
                f"{humanfriendly.format_size(len(response_bytes), binary=True)}. "
                f"See the attached burp report for details."
            )
        )
    except UnicodeDecodeError:
        response = "Could not decode response as text."

    return {"request": request, "response": response}
