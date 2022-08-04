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

from gaussian.issue_refinement.refinement.scan_tools.aqua_trivy.normalizer import (
    get_severity_value,
    purge_escape_characters,
)


@pytest.mark.parametrize(
    "level, expected",
    [
        ("INFORMATION", 0),
        ("LOW", 3),
        ("MEDIUM", 6),
        ("HIGH", 8),
        ("CRITICAL", 10),
        ("None", -1),
    ],
)
def test_get_severity_value(level, expected):
    severity_results = get_severity_value(level)
    assert severity_results == expected


@pytest.mark.parametrize(
    "issue, expected",
    [
        ({"value1": "Hello world"}, {"value1": "Hello world"}),
        ({"value1": "\tH\nell\\no w\ro\\rrld"}, {"value1": "Hello world"}),
    ],
)
def test_purge_escape_characters(issue, expected):
    pruned_results = purge_escape_characters(issue)
    assert pruned_results == expected
