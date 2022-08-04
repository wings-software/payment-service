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

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC
from gaussian.utils.text_scrapers import scrape_reference_identifier

issue_schema = {
    "issueName": {"type": "string", "required": True},
    "scanTool": {"type": "string", "required": True},
    "severity": {"type": "number", "min": 0, "max": 10, "required": True},
    "key": {"type": "string", "required": True},
    "alert": {"type": "boolean", "required": False},
    "ignore": {"type": "boolean", "required": False},
    "vulnerabilityDetails": {"type": "list", "required": False},
    "identifiers": {"type": "list", "required": False},
}


def validate_issue(validator, issue):
    valid = validator.validate(issue, issue_schema)
    if not valid:
        err = validator.errors
        raise ValueError(err)


def change_case(instr):
    """
    Change from camelCase to snake_case
    """
    res = [instr[0].lower()]
    for char in instr[1:]:
        if char in ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
            res.append("_")
            res.append(char.lower())
        else:
            res.append(char)
    return "".join(res)


class Refiner(RefinerABC):
    def __init__(self):
        self.key_config = []
        self.common_attributes = []
        self.reference_identifiers_prefix = []
        self.reference_identifiers_key = None

    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        try:
            if type(binary_data) == bytes:
                binary_data = binary_data.decode("utf8")
            data = json.loads(binary_data)

            meta = data.get("meta")
            issues = data.get("issues", [])
            self.key_config = meta.get("key", []) if meta else None

            if meta:
                raw_common_attributes = meta.get("commonAttributes")
                if raw_common_attributes and isinstance(raw_common_attributes, list):
                    self.common_attributes = [
                        change_case(ca) for ca in raw_common_attributes
                    ]

                raw_reference_identifiers = meta.get("referenceIdentifiers")
                if raw_reference_identifiers and isinstance(
                    raw_reference_identifiers, dict
                ):
                    self.reference_identifiers_key = raw_reference_identifiers.get(
                        "key"
                    )
                    self.reference_identifiers_prefix = raw_reference_identifiers.get(
                        "prefix"
                    )
                    if self.reference_identifiers_prefix and isinstance(
                        self.reference_identifiers_prefix, str
                    ):
                        self.reference_identifiers_prefix = (
                            self.reference_identifiers_prefix.split(",")
                        )
                    elif not self.reference_identifiers_prefix:
                        self.reference_identifiers_prefix = ["CVE", "CWE"]

            return {"issues": issues, "extra_data": {"meta": meta}}
        except ValueError as err:
            logging.error(f"Failed to load raw issues: {err}")
            raise ValueError(err)

    def normalizer(self, issue):
        new_issue = dict()
        for key, value in issue.items():
            cased_key = change_case(key)
            new_issue[cased_key] = value

        if self.key_config:
            key_data = "//".join([issue.get(dict_key) for dict_key in self.key_config])
            new_issue["key"] = key_data
            new_issue["key_values"] = [
                dict_key for dict_key in self.key_config if dict_key
            ]

        reference_identifiers = new_issue.get("reference_identifiers")
        if not reference_identifiers:
            reference_identifiers = list()
            r_value = new_issue.get(self.reference_identifiers_key)
            if r_value:
                new_identifiers = scrape_reference_identifier(
                    r_value, prefix=self.reference_identifiers_prefix
                )
                reference_identifiers.extend(
                    [x for x in new_identifiers if x not in reference_identifiers]
                )
                new_issue["reference_identifiers"] = reference_identifiers

        return new_issue
