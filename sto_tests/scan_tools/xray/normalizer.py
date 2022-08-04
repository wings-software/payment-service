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
from gaussian.utils.helper_funcs import rehydrate
from gaussian.utils.text_scrapers import scrape_reference_identifier


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        output = json.loads(binary_data.decode("utf8"))
        if isinstance(output, list):
            if len(output) == 1:
                output = output[0]
            elif len(output) == 0:
                return []

        artifacts = output.get("artifacts", [])

        if not len(artifacts) >= 1:
            return []

        return rehydrate(artifacts[0]["issues"])

    def normalizer(self, issue):
        lib, version = None, None
        try:
            lib, version = issue["impact_path"][0].split("/")[-1].split(":", 1)
        except Exception:
            return None

        scan_severity = issue.get("severity", None)

        cvss_severity = None
        cvss_vector = None
        cvss_data = None
        cve_data = []
        cwe_data = []

        reference_identifiers = []

        if issue.get("cves", None) is not None:
            severities_list = ["0.0"]

            for cve in issue.get("cves", []):
                if isinstance(cve, dict):
                    cve = cve.get("cve", None)

                if cve is None:
                    continue
                else:
                    cve_data.append(cve)

                try:
                    vuln_data = self.config.redis.get(cve)
                except Exception:
                    vuln_data = None

                impact = {}
                svrity = None
                vector = None
                if vuln_data is not None:
                    r_data = json.loads(vuln_data)
                    impact = r_data.get("impact")

                if "baseMetricV2" in impact and "cvssV2" in impact["baseMetricV2"]:
                    svrity = str(
                        impact.get("baseMetricV2", {})
                        .get("cvssV2", {})
                        .get("baseScore", "0.0")
                    )
                    vector = (
                        impact.get("baseMetricV2", {})
                        .get("cvssV2", {})
                        .get("vectorString", None)
                    )

                if "baseMetricV3" in impact and "cvssV3" in impact["baseMetricV3"]:
                    svrity = str(
                        impact.get("baseMetricV3", {})
                        .get("cvssV3", {})
                        .get("baseScore", "0.0")
                    )
                    vector = (
                        impact.get("baseMetricV3", {})
                        .get("cvssV3", {})
                        .get("vectorString", None)
                    )

                if svrity is not None and svrity > max(severities_list):
                    cvss_vector = vector

                if svrity is not None:
                    severities_list.append(svrity)
                reference_identifiers.extend(scrape_reference_identifier(cve))

            for cwe in issue.get("cves", []):
                if isinstance(cwe, dict):
                    cwe = cwe.get("cwe", None)

                if cwe is None:
                    continue
                else:
                    cwe_data.append(cwe)

                try:
                    vuln_data = self.config.redis.get(cwe)
                except Exception:
                    vuln_data = None

                impact = {}
                svrity = None
                vector = None
                if vuln_data is not None:
                    r_data = json.loads(vuln_data)
                    impact = r_data.get("impact")

                    if "baseMetricV2" in impact and "cvssV2" in impact["baseMetricV2"]:
                        svrity = str(
                            impact.get("baseMetricV2", {})
                            .get("cvssV2", {})
                            .get("baseScore", "0.0")
                        )
                        vector = (
                            impact.get("baseMetricV2", {})
                            .get("cvssV2", {})
                            .get("vectorString", None)
                        )

                    if "baseMetricV3" in impact and "cvssV3" in impact["baseMetricV3"]:
                        svrity = str(
                            impact.get("baseMetricV3", {})
                            .get("cvssV3", {})
                            .get("baseScore", "0.0")
                        )
                        vector = (
                            impact.get("baseMetricV3", {})
                            .get("cvssV3", {})
                            .get("vectorString", None)
                        )

                    if svrity is not None and svrity > max(severities_list):
                        cvss_vector = vector

                    if svrity is not None:
                        severities_list.append(svrity)
                reference_identifiers.extend(scrape_reference_identifier(cwe))

        cvss_data = max(list(filter(None, severities_list)))
        cvss_severity = cvss_data

        severity = cvss_severity

        if scan_severity == "Negligible":
            severity = 0

        description = None
        if "description" in issue:
            description = issue["description"]

        namespace = None
        if "impact_path" in issue:
            namespace = issue["impact_path"][-1]

        key = f"{lib}//{version}"
        key_values = ["library_name", "current_version"]

        if "+" in key:
            key = re.sub(r"\+(.*)$", "", key)

        if ".el" in key and re.search(r"\.el(.*)$", key) is not None:
            key = re.sub(r"\.el(.*)$", "", key)

        if severity is None:
            severity = float(0)

        return {
            "issue_name": key,
            "issue_description": description,
            "image_namespaces": namespace,
            "reference_identifiers": reference_identifiers,
            "severity": severity,
            "scan_severity": scan_severity,
            "key": key,
            "key_values": key_values,
            "library_name": lib,
            "current_version": version,
            "cve": cve_data,
            "cvss": cvss_data,
            "cvss_vector": cvss_vector,
        }
