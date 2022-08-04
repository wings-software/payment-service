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
from gaussian.utils.helper_funcs import get_severity_value, strip_cwe_cve


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        try:
            data = binary_data.decode("utf8")
            output = json.loads(data)
            if not isinstance(output, list):
                output = [output]
            return output
        except ValueError as err:
            config.logger.error(f"Failed to load raw issues: {err}")
            raise err

    def normalizer(self, issue):
        library_name = issue.get("package_name", "!(package_name:nil)!")
        current_version = issue.get("installed_version", "!(package_version:nil)!")

        scan_severity = issue["cve_severity"]
        cvss_severity = None
        cvss_vector = None

        if issue.get("metadata", None) is not None:
            if "CVSSv3" in issue["metadata"]["NVD"]:
                cvss_data = issue["metadata"]["NVD"]["CVSSv3"]
            elif "CVSSv2" in issue["metadata"]["NVD"]:
                cvss_data = issue["metadata"]["NVD"]["CVSSv2"]

            cvss_severity = cvss_data["Score"]
            cvss_vector = cvss_data["Vectors"]

        severity = cvss_severity

        if scan_severity == "Negligible":
            severity = 0.0

        if severity is None:
            severity = get_severity_value(scan_severity)

        issue_name = issue.get("cve_name", "")
        if "CVE-" in issue_name:
            cve = strip_cwe_cve(issue_name)
        else:
            cve = None

        description = None
        if "cve_desc" in issue:
            description = issue["cve_desc"]
        else:
            description = issue_name

        namespace = None
        if "namespace_name" in issue:
            namespace = issue["namespace_name"]

        key = f"{library_name}"
        key_values = ["library_name"]

        if "+" in key:
            key = re.sub(r"\+(.*)$", "", key)

        if ".el" in key and re.search(r"\.el(.*)$", key) is not None:
            key = re.sub(r"\.el(.*)$", "", key)

        return {
            "issue_name": issue_name,
            "issue_description": description,
            "image_namespaces": namespace,
            "severity": severity,
            "scan_severity": scan_severity,
            "cve": cve,
            "key": key,
            "key_values": key_values,
            "library_name": library_name,
            "image_layer_id": issue.get("image_layer", None),
            "current_version": current_version,
            "cvss_vector": cvss_vector,
        }
