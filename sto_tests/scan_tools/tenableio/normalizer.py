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

import coalesce

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        issues = []
        data = json.loads(binary_data.decode("utf-8"))

        hosts = data.get("hosts", [])

        for host in hosts:
            host_info = host.get("info", {})
            vulnerabilities = host.get("vulnerabilities", [])
            hostname = (
                host_info.get("host-ip")
                or host_info.get("host-fqdn")
                or host_info.get("mac-address")
            )
            for vulnerability in vulnerabilities:
                if isinstance(vulnerability, dict):
                    vulnerability["hostname"] = hostname
            issues.extend(vulnerabilities)
        return issues

    def normalizer(self, issue):
        host = issue.get("hostname")
        key = host
        key_values = ["host"]
        delimiter = ""
        plugin_data = issue.get("plugin_info", {}).get("plugindescription", {})
        plugin_output = issue.get("plugin_output", [])
        plugin_info = plugin_data.get("pluginattributes", {})
        scan_severity = plugin_data.get("severity")
        severity = self.get_severity(scan_severity)
        cvss_hash = plugin_info.get("risk_information", None)
        cvss_base, cvss_vector = None, None
        if cvss_hash is not None:
            if "cvss_base_score" in cvss_hash:
                cvss_base = float(cvss_hash["cvss_base_score"])
            if "cvss_vector" in cvss_hash:
                cvss_vector = cvss_hash["cvss_vector"]

        identifiers = []
        cwe = plugin_info.get("cwe", None)
        cve = plugin_info.get("cve", None)
        if cwe is not None:
            identifiers.append({"type": "cwe", "id": cwe})
        if cve is not None:
            identifiers.append({"type": "cve", "id": cve})

        vulnerability_details = []

        for output_entry in plugin_output:
            vulnerability_details.append(
                {
                    "output": output_entry.get("plugin_output"),
                    "severity": output_entry.get("severity"),
                    "custom_description": output_entry.get("custom_description"),
                    "ports": list(
                        map(
                            lambda x: x.split("/")[0].strip(),
                            output_entry.get("ports", {}).keys(),
                        ),
                    ),
                },
            )

        return {
            "issue_name": plugin_data.get("pluginname")
            or plugin_info.get("plugin_name", ""),
            "issue_description": plugin_info.get("description", ""),
            "scan_severity": scan_severity,
            "target": host,
            "host": host,
            "severity": coalesce.coalesce(
                [cvss_base, severity],
                ignore=None,
                default=1,
            ),
            "cvss": cvss_base,
            "cvss_vector": cvss_vector,
            "reference_identifiers": identifiers,
            "remediation_steps": self.build_remediation_steps(plugin_info),
            "vulnerability_details": vulnerability_details,
            "key": key,
            "key_values": key_values,
            "delimiter": delimiter,
        }

    @classmethod
    def get_severity(cls, level: int) -> int:
        # Tenableio outpus levels 0-4: Informational, Low Risk, Medium Risk, High
        # Risk, and Critical Risk

        if level == 0:
            return 0
        elif level == 1:
            return 3
        elif level == 2:
            return 6
        elif level == 3:
            return 8
        elif level == 4:
            return 10
        else:
            return -1

    @classmethod
    def build_remediation_steps(cls, plugin_info):
        syn = plugin_info.get("synopsis", None)
        sol = plugin_info.get("solution", None)
        see = plugin_info.get("see_also", None)

        if syn is not None:
            syn = syn.strip()
        else:
            syn = ""

        if sol is not None:
            sol = f" {sol}"
        else:
            sol = ""

        if see is not None:
            see = ", ".join(see)
            see = f" See also: {see}"
        else:
            see = ""

        return syn + sol + see
