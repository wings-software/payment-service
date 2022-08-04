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

import requests

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.issue_refinement.refinement.product_info import ScanTypeInfo
from gaussian.utils.text_scrapers import scrape_reference_identifier

severity_dictionary = {"INFO": 0, "MINOR": 3, "MAJOR": 6, "CRITICAL": 8, "BLOCKER": 10}

severity_dictionary_enum = {
    "INFO": "Information",
    "MINOR": "Low",
    "MAJOR": "Medium",
    "CRITICAL": "High",
    "BLOCKER": "Critical",
}


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        sonarqube_output = json.loads(binary_data.decode("utf8"))
        stats = sonarqube_output.get("stats")
        extra_data = {}
        # open_issues = [issue for issue in sonarqube_issues if issue['status'] == 'OPEN']
        for k in stats:
            metric = k.get("metric")
            value = k.get("value")
            if metric == "ncloc":
                extra_data["linesScanned"] = value
            elif metric == "bugs":
                extra_data["bugs"] = value
            elif metric == "coverage":
                extra_data["coverage"] = value
            elif metric == "code_smells":
                extra_data["codeSmells"] = value
            elif metric == "security_rating":
                extra_data["securityRating"] = value
            elif metric == "vulnerabilities":
                extra_data["Vulnerabilities"] = value
        return {
            "issues": [
                issue
                for issue in sonarqube_output.get("issues")
                if issue.get("type") == "VULNERABILITY"
            ],
            "extra_data": extra_data,
        }

    def normalizer(self, issue):
        scan_status = issue.get("status")
        if scan_status == "RESOLVED":
            return None
        scan_severity = issue.get("severity")
        severity = severity_dictionary.get(scan_severity, -1)
        scan_status = issue.get("status")
        tracking_severity = severity_dictionary_enum.get(scan_severity)
        message = issue.get("message")
        project = issue.get("project")
        file_name = issue.get("component", "").split(":")[-1]
        line_number = issue.get("line")
        author = issue.get("author")
        issue_type = issue.get("type")
        rule = issue.get("rule")
        link = issue.get("link")
        effort = issue.get("effort")
        scan_id = issue.get("key")
        key = rule
        key_values = ["rule"]

        new_issue = {
            "issue_name": message,
            "issue_description": message,
            "issue_type": issue_type,
            "author": author,
            "file_name": file_name,
            "scan_severity": scan_severity,
            "tracking_severity": tracking_severity,
            "scan_status": scan_status,
            "scan_id": scan_id,
            "rule": rule,
            "line_number": line_number,
            "project": project,
            "effort": effort,
            "severity": severity,
            "link": link,
            "key": key,
            "key_values": key_values,
            "scan_type": ScanTypeInfo.SAST,
        }
        rules = issue.get("rule_search_data", {}).get("rules")
        if rules:
            remediation_steps, reference_identifiers = self.parse_rules(
                rules[0].get("htmlDesc")
            )
            new_issue["remediation_steps"] = remediation_steps
            new_issue["reference_identifiers"] = reference_identifiers

        textRange = issue.get("textRange", {})
        if "startLine" in textRange and "endLine" in textRange:
            new_issue["lines_of_code_impacted"] = (
                textRange["endLine"] - textRange["startLine"] + 1
            )
        return new_issue

    def supplemental_data(self, config, binary_data, target=None, policy=None):
        extra_data = {}
        bug_counts = {}
        codesmell_counts = {}
        extra_data["underlyingBugCounts"] = bug_counts
        extra_data["underlyingCodeSmellCounts"] = codesmell_counts
        sonarqube_issues = json.loads(binary_data.decode("utf8"))
        supplemental_issues = [
            issue
            for issue in sonarqube_issues.get("issues")
            if issue["type"] in ["CODE_SMELL", "BUG"]
        ]
        for issue in supplemental_issues:
            scan_severity = issue.get("severity")
            issue_type = issue.get("type")
            if issue_type == "BUG":
                tracker = bug_counts
            elif issue_type == "CODE_SMELL":
                tracker = codesmell_counts

            tracking_severity = severity_dictionary_enum[scan_severity]
            if tracking_severity not in tracker:
                tracker[tracking_severity] = 0
            tracker[tracking_severity] += 1

        return {
            "issues": supplemental_issues,
            "extra_data": extra_data,
        }

    def enrichment(self, issue):
        if issue.remediation_steps:
            """
            We should skip enrichment if we get customer created remediation_steps
            from sonarqubes api
            """
            return issue

        issue_rule = issue.rule
        if issue_rule is None:
            return issue

        rule_parts = issue_rule.split(":")
        rule_type = rule_parts[0]
        rule_id = rule_parts[1]
        if rule_type == "javascript":
            url = (
                f"https://raw.githubusercontent.com/SonarSource/sonar-javascript/master/"
                f"javascript-checks/src/main/resources/org/sonar/l10n/javascript/rules/javascript/{rule_id}.html"
            )
        elif rule_type == "python":
            url = (
                f"https://raw.githubusercontent.com/SonarSource/sonar-python/master/"
                f"python-checks/src/main/resources/org/sonar/l10n/py/rules/python/{rule_id}.html"
            )
        elif rule_type == "php":
            url = (
                f"https://raw.githubusercontent.com/SonarSource/sonar-php/master/"
                f"php-checks/src/main/resources/org/sonar/l10n/php/rules/php/{rule_id}.html"
            )
        elif rule_type == "java":
            url = (
                f"https://raw.githubusercontent.com/SonarSource/sonar-java/master/"
                f"java-checks/src/main/resources/org/sonar/l10n/java/rules/java/{rule_id}_java.html"
            )
        elif rule_type == "squid":
            url = (
                f"https://raw.githubusercontent.com/SonarSource/sonar-java/master/"
                f"java-checks/src/main/resources/org/sonar/l10n/java/rules/squid/{rule_id}_java.html"
            )
        elif rule_type == "cs":
            url = (
                f"https://raw.githubusercontent.com/SonarSource/sonaranalyzer-dotnet/"
                f"master/src/SonarAnalyzer.Utilities/Rules.Description/{rule_id}_cs.html"
            )
        elif rule_type == "csharpsquid":
            url = (
                f"https://raw.githubusercontent.com/SonarSource/sonar-csharp/master/sonaranalyzer-dotnet/"
                f"src/SonarAnalyzer.Utilities/Rules.Description/{rule_id}.html"
            )
        elif rule_type == "vb":
            url = (
                f"https://raw.githubusercontent.com/SonarSource/sonaranalyzer-dotnet/"
                f"master/src/SonarAnalyzer.Utilities/Rules.Description/{rule_id}_vb.html"
            )
        else:
            return issue

        try:
            steps = self.get_rule(url)
            remediation_steps, reference_identifiers = self.parse_rules(steps)
            issue.remediation_steps = remediation_steps
            issue.reference_identifiers.extend(
                [
                    x
                    for x in reference_identifiers
                    if x not in issue.reference_identifiers
                ],
            )
        except BaseException:
            return issue

        return issue

    def parse_rules(self, steps):
        """
        Converts the html description into remediation_steps and cve data
        """
        steps = f"<div>{str(steps)}</div>"
        a_href = "<a href="
        replacement_href = '<a target="_blank" href='
        steps = steps.replace(a_href, replacement_href)

        reference_identifiers = []
        reference_identifiers = [
            x
            for x in scrape_reference_identifier(steps)
            if x not in reference_identifiers
        ]

        return steps, reference_identifiers

    def get_rule(self, url):
        response = requests.get(url)
        code = response.status_code
        if code >= 400:
            raise Exception(
                f"Unable to make get request to {url}. Status: {code} err:{response.text or response.reason}",
            )

        return response.text
