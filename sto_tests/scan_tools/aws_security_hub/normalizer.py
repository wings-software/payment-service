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


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        result = {"issues": [], "extra_data": {}}
        try:
            data = json.loads(binary_data.decode("utf-8"))
            result["issues"] = data["Findings"]
        except Exception as ex:
            config.logger.error(ex)
            raise

        return result

    def normalizer(self, issue):
        regex_instance = re.compile(r"i-\w+", re.IGNORECASE)
        regex_ip_address = re.compile(r"[0-9]+(?:\.[0-9]+){3}", re.IGNORECASE)
        regex_eks = re.compile(r"\w+-eks\w+", re.IGNORECASE)
        instance_replacement = "<specific instance listed in details>"
        ip_address_replacement = "<specific ip listed in details>"
        eks_replacement = "<specific eks instance listed in details>"

        max_scan_severity = 1.0

        if issue.get("Compliance", {}).get("Status") == "PASSED":
            return None

        schema_version = None
        if "SchemaVersion" in issue:
            schema_version = issue["SchemaVersion"]

        issue_id = None
        if "Id" in issue:
            issue_id = issue["Id"]

        product_arn = None
        if "ProductArn" in issue:
            product_arn = issue["ProductArn"]

        generator_id = None
        if "GeneratorId" in issue:
            generator_id = issue["GeneratorId"]

        aws_account_id = None
        if "AwsAccountId" in issue:
            aws_account_id = issue["AwsAccountId"]

        issue_types = []
        if "Types" in issue:
            issue_types = issue["Types"]

        first_observed_at = None
        if "FirstObservedAt" in issue:
            first_observed_at = issue["FirstObservedAt"]

        last_observed_at = None
        if "LastObservedAt" in issue:
            last_observed_at = issue["LastObservedAt"]

        created_at = None
        if "CreatedAt" in issue:
            created_at = issue["CreatedAt"]

        updated_at = None
        if "UpdatedAt" in issue:
            updated_at = issue["UpdatedAt"]

        product_severity = None
        normalized_severity = None
        if "Severity" in issue:
            product_severity = issue.get("Severity", {}).get("Product", None)
            normalized_severity = issue.get("Severity", {}).get(
                "Normalized",
                -1,
            )

            if normalized_severity is not None:
                val = float(normalized_severity)
                if is_severity_bigger(
                    val,
                    max_scan_severity,
                ):
                    max_scan_severity = get_instance_severity(val)

        title = None
        if "Title" in issue:
            title = issue["Title"]

        description = None
        if "Description" in issue:
            description = issue["Description"]

        product_fields = {}
        product_fields_type = "Unknown"
        product_fields_name = "Unknown"
        product_fields_resource_role = "Unknown"
        product_fields_lat = None
        product_fields_long = None
        if "ProductFields" in issue:
            product_fields = issue["ProductFields"]

            if "RelatedAWSResources:0/name" in issue["ProductFields"]:
                product_fields_name = issue["ProductFields"][
                    "RelatedAWSResources:0/name"
                ]

            if "RelatedAWSResources:0/type" in issue["ProductFields"]:
                product_fields_type = issue["ProductFields"][
                    "RelatedAWSResources:0/type"
                ]

            if "resourceRole" in issue["ProductFields"]:
                product_fields_resource_role = issue["ProductFields"]["resourceRole"]

            if (
                "action/networkConnectionAction/remoteIpDetails/geoLocation/lat"
                in issue["ProductFields"]
            ):
                product_fields_lat = issue["ProductFields"][
                    "action/networkConnectionAction/remoteIpDetails/geoLocation/lat"
                ]

            if (
                "action/networkConnectionAction/remoteIpDetails/geoLocation/lon"
                in issue["ProductFields"]
            ):
                product_fields_long = issue["ProductFields"][
                    "action/networkConnectionAction/remoteIpDetails/geoLocation/lon"
                ]

        resources = []
        if "Resources" in issue:
            resources_raw = issue["Resources"]
            if isinstance(resources_raw, dict):
                resources_raw = [resources_raw]

            if len(resources_raw) > 0:
                resource_type = resources_raw[0].get("Type")
                for resource in resources_raw:
                    resources.append(resource.get("Id"))

        workflow_state = None
        if "WorkflowState" in issue:
            workflow_state = issue["WorkflowState"]

        record_state = None
        if "RecordState" in issue:
            record_state = issue["RecordState"]

        issue_key = f"{generator_id}//{resource_type}"

        return {
            "issue_name": regex_eks.sub(
                eks_replacement,
                regex_ip_address.sub(
                    ip_address_replacement,
                    regex_instance.sub(
                        instance_replacement,
                        title,
                    ),
                ),
            ),
            "issue_description": regex_ip_address.sub(
                ip_address_replacement,
                regex_instance.sub(
                    instance_replacement,
                    description,
                ),
            ),
            "scan_severity": max_scan_severity,
            "severity": max_scan_severity,
            "key": issue_key,
            "key_values": ["generator_id", "resource_type"],
            "vulnerability_details": product_fields,
            "schema_version": schema_version,
            "product_arn": product_arn,
            "generator_id": generator_id,
            "aws_account_id": aws_account_id,
            "issue_types": issue_types,
            "first_observed_at": first_observed_at,
            "last_observed_at": last_observed_at,
            "created_at": created_at,
            "updated_at": updated_at,
            "resources": resources,
            "workflow_state": workflow_state,
            "record_state": record_state,
            "issue_id": issue_id,
            "product_name": product_fields_name,
            "product_type": product_fields_type,
            "resource_role": product_fields_resource_role,
            "resource_type": resource_type,
            "product_severity": product_severity,
            "action_lat": product_fields_lat,
            "action_long": product_fields_long,
        }


def get_instance_severity(level):
    """
    Normalized Label
    0      | INFORMATIONAL
    1–39   | LOW
    40–69  | MEDIUM
    70–89  | HIGH
    90–100 | CRITICAL
    Based on https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub.pdf
    """
    if level == 0.0:  # information
        return 0
    elif level >= 1 and level < 40:  # low
        return 3
    elif level >= 40 and level < 70:  # medium 40
        return 6
    elif level >= 70 and level < 90:  # high 70
        return 8
    elif level >= 90 and level <= 100:  # critical
        return 10
    return -1


def is_severity_bigger(a, b):
    return get_instance_severity(a) > get_instance_severity(b)
