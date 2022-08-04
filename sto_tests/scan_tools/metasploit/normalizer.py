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

import re

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC


def base_output_hash():
    return {
        "warning": {"issues": [], "delimiter": "!"},
        "debug": {"issues": [], "delimiter": "*"},
        "success": {"issues": [], "delimiter": "+"},
        "failure": {"issues": [], "delimiter": "-"},
    }


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        data = binary_data.decode("utf8")
        output = base_output_hash()
        parsed = [line.rstrip("\n") for line in data.splitlines()]

        for _, line in enumerate(parsed):
            for key in output.keys():
                delm = output[key]["delimiter"]
                regx = r"^\[\{0}\]\W(.*)$".format(delm)

                if re.search(regx, line):
                    output[key]["issues"].append(line)

        metasploit_issues = output["success"]["issues"]
        return metasploit_issues

    def normalizer(self, issue):
        fields_delimiter = "==CYBRIC-FIELDS=="
        array_field_name_delimiter = "=CYBRIC-ARRAY-FIELD="
        string_field_name_delimiter = "=CYBRIC-STRING-FIELD="

        issue_fields = issue.split(fields_delimiter)
        issue_description = issue_fields[0].replace("[+]", "")
        issue_name = issue_description[:30]
        new_issue = {
            "issue_name": issue_name,
            "issue_description": issue_description,
            "severity": 10,
            "key": issue_description,
            "key_values": ["issue_description"],
        }

        if len(issue_fields) > 1:
            index = 1
            while index < len(issue_fields):
                extra_array_field = issue_fields[index].split(
                    array_field_name_delimiter,
                )
                extra_string_field = issue_fields[index].split(
                    string_field_name_delimiter,
                )

                if len(extra_array_field) == 2:
                    field_name = extra_array_field[0]
                    field_value = extra_array_field[1].split(",")
                    new_issue[field_name] = field_value

                if len(extra_string_field) == 2:
                    field_name = extra_string_field[0]
                    field_value = extra_string_field[1]
                    new_issue[field_name] = field_value
                index += 1

        return new_issue
