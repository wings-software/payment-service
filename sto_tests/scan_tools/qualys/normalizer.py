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

import base64
import json
import logging

import xmltodict

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.utils.text_scrapers import scrape_reference_identifier


def get_severity(level: str) -> int:
    # Qualys outpus levels 1-5: Minimal, Medium, Serious, Critical, Urgent
    if level == "1":
        return 0
    elif level == "2":
        return 3
    elif level == "3":
        return 6
    elif level == "4":
        return 8
    elif level == "5":
        return 10
    else:
        return -1


def remove_cdata(text_string: str) -> str:
    if text_string and isinstance(text_string, str):
        clean_string = text_string.replace("<![CDATA[", "")
        return clean_string.replace("]]>", "")
    return ""


class Refiner(RefinerABC):
    def __init__(self):
        self.report_type = ""
        self.qids_list = {}
        self.vuln_lookups = {}

    def get_qids_list(self, qids):
        if isinstance(qids, dict):
            qids = [qids]
        if not isinstance(qids, list):
            raise Exception("Qualys report does not contain QID_LIST")

        for qid in qids:
            new_lookup = {
                "issue_name": qid.get("TITLE"),
                "issue_type": qid.get("CATEGORY"),
                "issue_description": remove_cdata(qid.get("IMPACT", "")),
                "remediation_steps": remove_cdata(qid.get("SOLUTION", "")),
                "scan_severity": qid.get("SEVERITY"),
                "severity": get_severity(qid.get("SEVERITY")),
                "description": remove_cdata(qid.get("DESCRIPTION", "")),
                "group": qid.get("GROUP"),
                "owasp": qid.get("OWASP"),
                "wasc": qid.get("WASC"),
                "cvss_base": qid.get("CVSS_BASE"),
                "cvss_temporal": qid.get("CVSS_TEMPORAL"),
                "common_attributes": [],
            }

            identifier_text = qid.get("CWE", "")
            identifiers = []
            identifiers.extend(scrape_reference_identifier(str(identifier_text)))
            new_lookup["reference_identifiers"] = identifiers
            self.qids_list[qid.get("QID")] = new_lookup

    def get_vuln_detail(self, vuln_details):
        for vuln_detail in vuln_details:
            issue_name = vuln_detail.get("TITLE", "")
            issue_type = vuln_detail.get("CATEGORY", "")
            issue_description_threat = vuln_detail.get("THREAT", "")
            issue_description_impact = vuln_detail.get("IMPACT", "")
            remediation_steps = remove_cdata(vuln_detail.get("SOLUTION", ""))
            scan_severity = vuln_detail.get("SEVERITY", "")
            severity = get_severity(vuln_detail.get("SEVERITY"))

            new_lookup = {
                "issue_name": issue_name,
                "issue_type": issue_type,
                "issue_description": f"{issue_description_threat} {issue_description_impact}",
                "remediation_steps": remediation_steps,
                "scan_severity": scan_severity,
                "severity": severity,
            }

            identifier_text = vuln_detail.get("CVE_ID_LIST", {}).get("CVE_ID", [])
            identifiers = []
            identifiers.extend(scrape_reference_identifier(str(identifier_text)))
            new_lookup["reference_identifiers"] = identifiers

            bugtraqs = vuln_detail.get("BUGTRAQ_ID_LIST", {}).get("BUGTRAQ_ID", [])

            if isinstance(bugtraqs, dict):
                bugtraqs = [bugtraqs]
            if isinstance(bugtraqs, list):
                for bugtraq in bugtraqs:
                    identifiers.append({"type": "bugtraq", "id": bugtraq.get("ID")})

            new_lookup["reference_identifiers"] = identifiers

            self.vuln_lookups[vuln_detail.get("@id")] = new_lookup

    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        source = xmltodict.parse(binary_data.decode("utf-8"))
        data = json.loads(json.dumps(source))

        report_definition_wsr = data.get("WAS_SCAN_REPORT", None)
        report_definition_wwr = data.get("WAS_WEBAPP_REPORT", None)
        report_definition_adr = data.get("ASSET_DATA_REPORT", None)

        if report_definition_wsr is not None:
            self.report_type = "WAS_SCAN_REPORT"
            report_definition = report_definition_wsr
            qids = report_definition.get("GLOSSARY", {}).get("QID_LIST", {}).get("QID")
            self.get_qids_list(qids)

            report_definition = report_definition_wsr

            vulnerability_list = (
                report_definition.get("RESULTS", {})
                .get("VULNERABILITY_LIST", {})
                .get("VULNERABILITY")
            )

            if isinstance(vulnerability_list, dict):
                vulnerability_list = [vulnerability_list]
            if not isinstance(vulnerability_list, list):
                raise Exception("Qualys report does not contain VULNERABILITY_LIST")

            for vuln in vulnerability_list:
                vuln["_type"] = "VULNERABILITY"

            info_list = (
                report_definition.get("RESULTS", {})
                .get("INFORMATION_GATHERED_LIST", {})
                .get("INFORMATION_GATHERED")
            )

            if isinstance(info_list, dict):
                info_list = [info_list]
            if not isinstance(info_list, list):
                raise Exception("Qualys report does not contain list of affected hosts")

            for info in info_list:
                info["_type"] = "INFORMATION_GATHERED"

            vulnerability_list.extend(info_list)

            return vulnerability_list

        elif report_definition_wwr is not None:
            self.report_type = "WAS_WEBAPP_REPORT"
            report_definition = report_definition_wwr
            qids = report_definition.get("GLOSSARY", {}).get("QID_LIST", {}).get("QID")
            self.get_qids_list(qids)

            results = (
                report_definition.get("RESULTS", {})
                .get("WEB_APPLICATION", {})
                .get("VULNERABILITY_LIST", {})
                .get("VULNERABILITY")
            )

            if isinstance(results, dict):
                results = [results]
            if not isinstance(results, list):
                raise Exception("Qualys report does not contain list of affected hosts")

            return results

        elif report_definition_adr is not None:
            self.report_type = "ASSET_DATA_REPORT"
            report_definition = report_definition_adr

            vuln_details = (
                report_definition.get("GLOSSARY", {})
                .get("VULN_DETAILS_LIST", {})
                .get("VULN_DETAILS")
            )

            if isinstance(vuln_details, dict):
                vuln_details = [vuln_details]
            if not isinstance(vuln_details, list):
                raise Exception(
                    "Qualys report does not contain vulnerability details sections",
                )

            self.get_vuln_detail(vuln_details)

            hosts = report_definition.get("HOST_LIST", {}).get("HOST", [])

            if isinstance(hosts, dict):
                hosts = [hosts]
            if not isinstance(hosts, list):
                raise Exception("Qualys report does not contain list of affected hosts")

            vulns = []
            for host in hosts:
                vulnerabilities = host.get("VULN_INFO_LIST", {}).get("VULN_INFO", [])
                if isinstance(vulnerabilities, dict):
                    vulnerabilities = [vulnerabilities]
                vulns.extend(vulnerabilities)
            return vulns
        else:
            raise Exception(
                "Scan type not one of WAS_SCAN_REPORT, WAS_WEBAPP_REPORT, ASSET_DATA_REPORT"
            )

    def normalizer(self, issue):
        if self.report_type == "WAS_SCAN_REPORT":
            return self.normalizer_report_definition_wsr(issue)
        elif self.report_type == "WAS_WEBAPP_REPORT":
            return self.normalizer_report_definition_wwr(issue)
        elif self.report_type == "ASSET_DATA_REPORT":
            return self.normalizer_report_definition_adr(issue)
        return

    def normalizer_report_definition_wsr(self, issue):
        if issue.get("_type") == "VULNERABILITY":
            vuln_id = issue.get("ID")
            lookupId = issue.get("QID")
            key = f"{lookupId}//{vuln_id}"
            key_values = ["lookup_id", "vuln_id"]

            if not lookupId:
                logging.error(f"Missing lookup id for vulnerability {issue}")
                return

            detail = self.qids_list.get(lookupId)

            if not detail:
                logging.error(f"Glossary of details does not contain {lookupId}")
                return

            new_issue = {
                "id": issue.get("ID"),
                "url": issue.get("URL"),
                "status": issue.get("STATUS"),
                "first_detected": issue.get("FIRST_TIME_DETECTED"),
                "last_detected": issue.get("LAST_TIME_DETECTED"),
                "group": issue.get("GROUP"),
                "owasp": issue.get("OWASP"),
                "wasc": issue.get("WASC"),
                "key": key,
                "vuln_id": vuln_id,
                "lookup_id": lookupId,
                "key_values": key_values,
            }
            new_issue.update(detail)
            return new_issue

        if issue.get("_type") == "INFORMATION_GATHERED":
            lookupId = issue.get("QID", {})
            if not lookupId:
                logging.error(f"Missing lookup id for info {issue}")
                return

            detail = self.qids_list.get(lookupId)

            if not detail:
                logging.error(f"Glossary of details does not contain {lookupId}")
                return

            data = issue.get("DATA")
            if data.get("@base64") == "true":
                data = base64.b64decode(data.get("#text"))
                data = data.decode("utf-8")
            info_id = issue.get("ID")
            key = f"{lookupId}//{info_id}"
            key_values = ["lookup_id", "info_id"]
            new_issue = {
                "id": info_id,
                "unique_id": issue.get("UNIQUE_ID"),
                "detection_id": issue.get("DETECTION_ID"),
                "first_detected": issue.get("FIRST_TIME_DETECTED"),
                "last_detected": issue.get("LAST_TIME_DETECTED"),
                "data": data,
                "key": key,
                "key_values": key_values,
                "lookup_id": lookupId,
                "info_id": info_id,
            }
            new_issue.update(detail)
            return new_issue
        return

    def normalizer_report_definition_wwr(self, issue):
        vuln_id = issue.get("ID")
        lookupId = issue.get("QID", {})
        if not lookupId:
            logging.error(f"Missing lookup id for vulnerability {issue}")
            return

        detail = self.qids_list.get(lookupId)

        if not detail:
            logging.error(f"Glossary of details does not contain {lookupId}")
            return

        key = f"{lookupId}//{vuln_id}"
        key_values = ["lookup_id", "vuln_id"]
        new_issue = {
            "key": key,
            "key_values": key_values,
            "lookup_id": lookupId,
            "vuln_id": vuln_id,
            "id": issue.get("ID"),
            "url": issue.get("URL"),
            "status": issue.get("STATUS"),
            "first_detected": issue.get("FIRST_TIME_DETECTED"),
            "last_detected": issue.get("LAST_TIME_DETECTED"),
            "group": issue.get("GROUP"),
            "owasp": issue.get("OWASP"),
            "wasc": issue.get("WASC"),
        }

        new_issue.update(detail)
        return new_issue

    def normalizer_report_definition_adr(self, issue):
        lookupId = issue.get("QID", {}).get("@id")
        if not lookupId:
            logging.error(
                f"Missing lookup id for vulnerability {issue}",
            )
            return

        detail = self.vuln_lookups.get(lookupId)

        if not detail:
            logging.error(
                f"Glossary of details does not contain {lookupId}",
            )
            return

        key = f"{lookupId}"
        key_values = ["lookup_id"]

        new_issue = {
            "port": issue.get("PORT"),
            "ip": issue.get("IP"),
            "host": issue.get("DNS"),
            "operatingSystem": issue.get("OPERATING_SYSTEM"),
            "trackingMethod": issue.get("TRACKING_METHOD"),
            "RESULT": issue.get("scanResult"),
            "key": key,
            "lookup_id": lookupId,
            "key_values": key_values,
            "url": issue.get("URL"),
            "status": issue.get("STATUS"),
            "first_detected": issue.get("FIRST_TIME_DETECTED"),
            "last_detected": issue.get("LAST_TIME_DETECTED"),
            # 'payloads': vulnerability.get('PAYLOADS'),
            "group": issue.get("GROUP"),
            "owasp": issue.get("OWASP"),
            "wasc": issue.get("WASC"),
        }

        new_issue.update(detail)
        return new_issue
