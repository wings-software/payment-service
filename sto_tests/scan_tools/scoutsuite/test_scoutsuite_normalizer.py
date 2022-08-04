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


import copy
import json
import os

import pytest
from deepdiff import DeepDiff

from gaussian.issue_refinement.ncis_coordinator import get_refined_issues
from gaussian.issue_refinement.refinement.product_info import ProductInfo
from gaussian.issue_refinement.refinement.scan_tools.scoutsuite.normalizer import (
    find_unpack_zip,
)
from tests.fixtures.config_fixture import ConfigFixture as Config
from tests.src.issue_refinement.scan_tools.mocks.message import MOCK_MESSAGE

""" setup the defaults for the tests """
CONFIG = Config()

policy_data = {}
policy_data["permanentRunOptions"] = {}
policy_data["targets"] = [{"name": "TestTarget"}]

test_data_path = "tests/src/issue_refinement/scan_tools/scoutsuite/"
expected_data_path = "tests/src/issue_refinement/scan_tools/scoutsuite/expected"


@pytest.mark.parametrize(
    "zip_name, expected",
    [
        ("test_data/fail-001.zip", ("ERROR", "no scoutsuite_results_*.js files found")),
        ("test_data/find-json-002.zip", 10),
        ("test_data/find-json-just-js-003.zip", 10),
        ("test_data/in-a-folder.zip", 10),
        ("test_data/just-the-file.js", 10),
        ("test_data/just-the-json.json", 10),
        (
            "test_data/blank-file.json",
            ("ERROR", "unexpected error loading the json data"),
        ),
    ],
    ids=[
        "001_fail",
        "002_find_json.zip",
        "003_find_json_just_js",
        "004_in_a_folder",
        "005_just_the_file",
        "006_just_the_json",
        "007_blank_file",
    ],
)
def test_find_unpack_zip(zip_name, expected):
    file_path = os.path.join(test_data_path, zip_name)
    with open(file_path, "rb+") as f:
        binary_data = f.read()
    result = find_unpack_zip(CONFIG.logger, binary_data)

    if expected and isinstance(expected, int):
        assert len(result.keys()) == expected
    else:  # no keys found!
        assert result == expected
