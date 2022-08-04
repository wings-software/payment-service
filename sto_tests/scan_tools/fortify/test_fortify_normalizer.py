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

from gaussian.issue_refinement.ncis_coordinator import get_refined_issues
from gaussian.issue_refinement.refinement.product_info import ProductInfo
from tests.fixtures.config_fixture import ConfigFixture as Config
from tests.src.issue_refinement.scan_tools.mocks.message import MOCK_MESSAGE

""" setup the defaults for the tests """
CONFIG = Config()

test_data_path = "tests/src/issue_refinement/scan_tools/fortify/test_data/"


@pytest.mark.parametrize(
    "file_name, expected_exception",
    [
        ("bad_data.txt", json.JSONDecodeError),
        ("bad_fortify_test_api_data.json", json.JSONDecodeError),
    ],
    ids=[
        "001_fail_wrong_file_type",
        "002_fail_bad_json_format",
    ],
)
def test_fortify_extract_raw_issues_data_load_error(file_name, expected_exception):
    file_path = os.path.join(test_data_path, file_name)
    with open(file_path, "rb+") as f:
        binary_data = f.read()

    with pytest.raises(expected_exception):
        message = copy.deepcopy(MOCK_MESSAGE)
        message["scenarioName"] = ProductInfo.FORTIFY
        message["productName"] = ProductInfo.FORTIFY
        ncis, extra_job_data, ncis_supplemental = get_refined_issues(
            CONFIG, binary_data, message
        )
