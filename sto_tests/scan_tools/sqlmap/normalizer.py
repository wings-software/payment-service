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

from gaussian.issue_refinement.refinement.abc.refiner import RefinerABC


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        return [
            {
                "issue_name": "SQLMap Default Report",
                "issue_type": "code[info]",
                "scan_tool": "SQLMap",
                "severity": 0,
                "issue_description": binary_data.decode("UTF-8"),
                "key": "SQLMap Default Report//code[info]",
                "key_values": ["issue_name", "issue_type"],
            },
        ]

    def normalizer(self, issue):
        return issue
