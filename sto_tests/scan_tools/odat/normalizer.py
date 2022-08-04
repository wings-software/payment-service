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


class Refiner(RefinerABC):
    def raw_issue_extractor(self, config, binary_data, policy_data=None):
        try:
            # Decode the data and get rid of the progress bars using the regex
            raw_data = binary_data.decode("UTF-8").strip()
            result = re.sub(r"^\s*\d*%.*\n", "", raw_data, flags=re.MULTILINE)
            raw_data = "".join(i for i in result if ord(i) < 128)

            # Roll up the data into an issue
            return [
                {
                    "issue_name": "ODAT Default Report",
                    "issue_type": "code[info]",
                    "scan_tool": "ODAT",
                    "severity": 0,
                    "issue_description": raw_data,
                    "key": "ODAT Default Report//code[info]",
                    "key_values": ["issue_name", "issue_type"],
                },
            ]

        except Exception as ex:
            config.logger.error(ex)
            raise

    def normalizer(self, issue):
        return issue
