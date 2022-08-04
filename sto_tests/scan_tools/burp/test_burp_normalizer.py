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

""" setup the defaults for the tests """
CONFIG = Config()

policy_data = {}
policy_data["permanentRunOptions"] = {}
policy_data["targets"] = [{"name": "TestTarget"}]
test_data_path = "tests/src/issue_refinement/scan_tools/burp/test_data/"


@pytest.mark.parametrize("binary_data_file", [("exception-001")])  # SAST & SCA
def test_exceptions(binary_data_file):
    file_path = os.path.join(test_data_path, binary_data_file)
    with open(file_path, "rb+") as f:
        binary_data = f.read()

    with pytest.raises(Exception):
        message = copy.deepcopy(MOCK_MESSAGE)
        message["scenarioName"] = ProductInfo.BURP
        message["productName"] = ProductInfo.BURP
        ncis, extra_job_data, ncis_supplemental = get_refined_issues(
            CONFIG, binary_data, message
        )
