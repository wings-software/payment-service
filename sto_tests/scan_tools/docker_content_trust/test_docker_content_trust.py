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
import os

import pytest

from gaussian.issue_refinement.ncis_coordinator import get_refined_issues
from gaussian.issue_refinement.refinement.product_info import ProductInfo
from tests.fixtures.config_fixture import ConfigFixture as Config
from tests.src.issue_refinement.scan_tools.mocks.message import MOCK_MESSAGE

CONFIG = Config()
test_data_path = "tests/src/issue_refinement/scan_tools/docker_content_trust/test_data/"


@pytest.mark.parametrize(
    "file_name, expected_exception",
    [
        ("bad_format.json", ValueError),
        ("bad_shape.json", ValueError),
    ],
    ids=[
        "001_fail_bad_file",
        "002_fail_bad_shape",
    ],
)
def test_docker_content_trust_issues_data_load_error(file_name, expected_exception):
    file_path = os.path.join(test_data_path, file_name)
    with open(file_path, "rb+") as f:
        binary_data = f.read()

    with pytest.raises(expected_exception):
        message = copy.deepcopy(MOCK_MESSAGE)
        message["scenarioName"] = ProductInfo.DOCKER_CONTENT_TRUST
        message["productName"] = ProductInfo.DOCKER_CONTENT_TRUST
        ncis, extra_job_data, ncis_supplemental = get_refined_issues(
            CONFIG, binary_data, message
        )
