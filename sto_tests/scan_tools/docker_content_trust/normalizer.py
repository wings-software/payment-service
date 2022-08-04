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

import cerberus

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.issue_refinement.refinement.product_info import ProductInfo


def validate_output(config=None, output=None):
    validator = cerberus.Validator()

    output_schema = {"result": {"type": "string"}, "trusted": {"type": "boolean"}}

    valid = validator.validate(output, output_schema)

    if not valid:
        err = validator.errors
        config.logger.error(f"Invalid docker-content-trust raw issue model: {err}")
        raise ValueError(err)


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        try:
            data = binary_data.decode("utf8")
            output = json.loads(data)

            validate_output(config=config, output=output)

            if not isinstance(output, list):
                output = [output]
            return {"issues": output, "extra_data": {}}
        except ValueError as err:
            config.logger.error(f"Failed to load raw issues: {err}")
            raise ValueError(str(err))

    def normalizer(self, issue):
        if not issue.get("trusted"):
            issue = {}
            issue_name = ProductInfo.DOCKER_CONTENT_TRUST
            issue["issue_name"] = issue_name
            issue["issue_description"] = issue.get("result", "Not trusted")
            issue["severity"] = 7
            issue["scan_tool"] = issue_name
            issue["key"] = issue_name
            issue["key_values"] = ["issue_name"]
            return issue
        return
