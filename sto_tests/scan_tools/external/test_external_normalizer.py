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


import pytest

from gaussian.issue_refinement.refinement.scan_tools.external.normalizer import (
    change_case,
)


@pytest.mark.parametrize(
    "instr, expected", [("getAssets", "get_assets"), ("get_vulns", "get_vulns")]
)
def test_validate_issue(instr, expected):
    resp = change_case(instr)
    assert resp == expected
