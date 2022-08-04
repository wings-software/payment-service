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

import coalesce
import xmltodict

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.issue_refinement.refinement.product_info import ScanTypeInfo
from gaussian.utils.helper_funcs import strip_cwe_cve


class Refiner(RefinerABC):
    def __init__(self):
        self.data_type = 0

    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        string_data = binary_data.decode("utf-8").strip()
        raw_issues = []
        try:
            raw_issues = json.loads(string_data)
            self.data_type = 1
            if isinstance(raw_issues, list) and len(raw_issues) == 0:
                return []
            return raw_issues["vulnerabilities"]
        except BaseException:
            self.data_type = 2
            raw_full = json.loads(json.dumps(xmltodict.parse(string_data)))
            keys = list(raw_full.keys())
            expected_keys = ["NessusClientData_v2"]
            if len(keys) > 1 or keys != expected_keys:
                raise Exception(
                    f"Unexpected key/values in Nessus.  Expect top level i.e. 'NessusClientData_v2', Keys were: {','.join(raw_full.keys())}"
                )
            nessus_data = (
                raw_full.get("NessusClientData_v2", {})
                .get("Report", {})
                .get("ReportHost", [])
            )
            if isinstance(nessus_data, list):
                hosts = nessus_data
            else:
                hosts = []
                hosts.append(nessus_data)
            if not hosts:
                raise Exception("Unable to parse output from Nessus into Issues")

            if isinstance(hosts, list) and len(hosts) == 0:
                return []
            items = []
            for host in hosts:
                target = host.get("@name")
                temp_items = host.get("ReportItem", [])
                if isinstance(temp_items, dict):
                    # the temp_items object will be a dict if there is only one item.
                    items.append(temp_items)
                elif isinstance(temp_items, list):
                    for item in temp_items:
                        item["target"] = target
                        items.append(item)
                else:
                    config.logger.warn(
                        f"Unexpected type. The type is:{type(temp_items)} and it should be a dict or list. Please review the file."
                    )
            return items

    def normalizer(self, issue):
        if self.data_type == 1:
            return self.normalizer_1(issue)
        if self.data_type == 2:
            return self.normalizer_2(issue)

    def normalizer_1(self, issue):
        if issue.get("details", None) is None:
            return
        else:
            if issue["details"].get("info", None) is None:
                return

        severity = issue["severity"]
        cvss_hash = (
            issue["details"]["info"]
            .get("plugindescription", {})
            .get("pluginattributes", {})
            .get("risk_information", None)
        )
        cvss_base, cvss_vector = None, None

        if cvss_hash is not None:
            if "cvss_base_score" in cvss_hash:
                cvss_base = float(cvss_hash["cvss_base_score"])
            if "cvss_vector" in cvss_hash:
                cvss_vector = cvss_hash["cvss_vector"]

        identifiers = []
        cwe = (
            issue["details"]["info"]
            .get("plugindescription", {})
            .get("pluginattributes", {})
            .get("cwe", None)
        )
        cve = (
            issue["details"]["info"]
            .get("plugindescription", {})
            .get("pluginattributes", {})
            .get("cve", None)
        )
        if cwe is not None:
            identifiers.append({"type": "cwe", "id": cwe})
        if cve is not None:
            identifiers.append({"type": "cve", "id": cve})

        issue_name = issue["plugin_name"]
        issue_id = str(issue_name)
        dirty_key = f"{issue_name}//{issue_id}"
        key = re.sub(r"[^a-zA-Z0-9 ]", "_", dirty_key)
        key_values = ["issue_name", "issue_id"]

        return {
            "issue_name": issue_name,
            "issue_id": issue_id,
            "issue_description": issue["details"]["info"]
            .get("plugindescription", {})
            .get("pluginattributes", {})
            .get("description", ""),
            "severity": coalesce.coalesce(
                [cvss_base, severity], ignore=None, default=1
            ),
            "cvss": cvss_base,
            "cvss_vector": cvss_vector,
            "reference_identifiers": identifiers,
            "remediation_steps": self._build_remediation_steps(issue),
            "vulnerability_details": issue["details"],
            "key": key,
            "key_values": key_values,
        }

    def normalizer_2(self, issue):
        severity = float(issue["@severity"])
        cvss_base = issue.get("cvss3_base_score", None)
        if not cvss_base:
            cvss_base = issue.get("cvss_base_score", None)
        if severity != 0 and cvss_base is not None:
            severity = float(cvss_base)

        port = issue.get("@port", None)
        protocol = issue.get("@protocol", None)
        plugin = issue.get("@pluginName", None)
        plugin_id = issue.get("@pluginID", None)
        plugin_family = issue.get("@pluginFamily", None)
        compliance_check_name = issue.get("cm:compliance-check-name", None)
        compliance_check_id = issue.get("cm:compliance-check-id", None)
        compliance_result = issue.get("cm:compliance-result", None)
        compliance_reference = issue.get("cm:compliance-reference", None)
        compliance_solution = issue.get("cm:compliance-solution", None)
        compliance_info = issue.get("cm:compliance-info", None)
        compliance_see_also = issue.get("cm:compliance-see-also", None)
        # compliance data has a compliance id and no cvss score
        if cvss_base is None and compliance_check_id is not None:
            # ignore compliance items that have passed
            if compliance_result == "PASSED":
                return None
            else:
                severity = self.convert_nessus_severity(severity)

        soln = issue.get("solution", None)
        soln = None if soln == "n/a" else soln
        cvss_vector = issue.get("cvss3_vector", None)
        if not cvss_vector:
            cvss_vector = issue.get("cvss_vector", None)
        description = issue.get("description", None)
        synopsis = issue.get("synopsis", None)
        link = issue.get("see_also", None)
        scan_severity = issue.get("risk_factor", None)
        plugin_output = issue.get("plugin_output", None)
        plugin_publication_date = issue.get("plugin_publication_date", None)
        identifiers = []
        cwe = issue.get("cwe", [])
        cve = issue.get("cve", [])
        xref = issue.get("xref", [])
        bid = issue.get("bid", [])
        if not isinstance(cwe, list):
            cwe = [cwe]
        if not isinstance(cve, list):
            cve = [cve]
        if not isinstance(xref, list):
            xref = [xref]
        if not isinstance(bid, list):
            bid = [bid]
        for vuln_id in cwe:
            identifiers.append({"type": "cwe", "id": strip_cwe_cve(vuln_id)})
        for vuln_id in cve:
            identifiers.append({"type": "cve", "id": strip_cwe_cve(vuln_id)})
        for entry in xref:
            parts = entry.split(":")
            if len(parts) == 2:
                identifiers.append(
                    {
                        "type": parts[0].lower(),
                        "id": strip_cwe_cve(parts[1]),
                    }
                )
        for vuln_id in bid:
            identifiers.append({"type": "bid", "id": vuln_id})

        key = f"{plugin_id}"
        key_values = ["plugin_id"]
        if compliance_check_id:
            key += f"//{compliance_check_id}"

        return {
            "issue_name": synopsis or plugin,
            "synopsis": synopsis,
            "issue_description": description,
            "severity": severity,
            "scan_severity": scan_severity,
            "cvss": cvss_base,
            "ip_address_/_host_name": issue.get("target"),
            "cvss_vector": cvss_vector,
            "reference_identifiers": identifiers,
            "remediation_steps": soln,
            "port": port,
            "protocol": protocol,
            "link": link or compliance_see_also,
            "plugin_output": plugin_output,
            "key": key,
            "key_values": key_values,
            "plugin_id": plugin_id,
            "plugin_name": plugin,
            "plugin_family": plugin_family,
            "plugin_publication_date": plugin_publication_date,
            "scan_type": ScanTypeInfo.DAST,
            "compliance_check_name": compliance_check_name,
            "compliance_check_id": compliance_check_id,
            "compliance_result": compliance_result,
            "compliance_reference": compliance_reference,
            "compliance_solution": compliance_solution,
            "compliance_info": compliance_info,
        }

    @classmethod
    def convert_nessus_severity(cls, severity):
        if severity == 0.0:
            return 0
        elif severity == 1.0:
            return 2
        elif severity == 2.0:
            return 6
        elif severity == 3.0:
            return 8
        else:
            return 0

    @classmethod
    def _build_remediation_steps(cls, issue):

        syn = (
            issue["details"]["info"]
            .get("plugindescription", {})
            .get("pluginattributes", {})
            .get("synopsis", None)
        )

        sol = (
            issue["details"]["info"]
            .get("plugindescription", {})
            .get("pluginattributes", {})
            .get("solution", None)
        )

        see = (
            issue["details"]["info"]
            .get("plugindescription", {})
            .get("pluginattributes", {})
            .get("see_also", None)
        )

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
