import copy
import json
import os

import pytest
from deepdiff import DeepDiff

from gaussian.issue_refinement.ncis_coordinator import get_refined_issues
from gaussian.issue_refinement.refinement.product_info import ProductInfo
from tests.fixtures.config_fixture import ConfigFixture as Config
from tests.src.issue_refinement.scan_tools.mocks.message import (
    MOCK_FORTIFYONDEMAND_DIRECT_MESSAGE,
    MOCK_FORTIFYONDEMAND_DYNAMIC_GITHUB_MESSAGE,
    MOCK_FORTIFYONDEMAND_GITHUB_MESSAGE,
    MOCK_FORTIFYONDEMAND_OPENSOURCE_GITHUB_MESSAGE,
    MOCK_FORTIFYONDEMAND_STATIC_GITHUB_MESSAGE,
    MOCK_MESSAGE,
)

CONFIG = Config()
tools_path = "tests/src/issue_refinement/scan_tools/"
test_data_dir = "test_data"
parametrized_tests_list = [
    (ProductInfo.APPSCAN, "001", MOCK_MESSAGE),
    (ProductInfo.APPSCAN, "002", MOCK_MESSAGE),
    (ProductInfo.AQUA_TRIVY, "001", MOCK_MESSAGE),
    (ProductInfo.AQUA_TRIVY, "002", MOCK_MESSAGE),
    (ProductInfo.AQUA_TRIVY, "003", MOCK_MESSAGE),
    (ProductInfo.AQUA_TRIVY, "004", MOCK_MESSAGE),
    (ProductInfo.AQUA_TRIVY, "005", MOCK_MESSAGE),
    (ProductInfo.AWS_SECURITY_HUB, "001", MOCK_MESSAGE),
    (ProductInfo.BANDIT, "001", MOCK_MESSAGE),
    (ProductInfo.BLACKDUCK, "001", MOCK_MESSAGE),
    (ProductInfo.BRAKEMAN, "001", MOCK_MESSAGE),
    (ProductInfo.BURP, "001", MOCK_MESSAGE),
    (ProductInfo.BURP, "002", MOCK_MESSAGE),
    (ProductInfo.BURP, "003", MOCK_MESSAGE),
    (ProductInfo.BURP, "004", MOCK_MESSAGE),
    (ProductInfo.CHECKMARX, "001", MOCK_MESSAGE),
    (ProductInfo.CHECKMARX, "002", MOCK_MESSAGE),
    (ProductInfo.CHECKMARX, "002", MOCK_MESSAGE),
    # (ProductInfo.COVERITY, "001", MOCK_MESSAGE),
    (ProductInfo.DATA_THEOREM, "001", MOCK_MESSAGE),
    (ProductInfo.DATA_THEOREM, "002", MOCK_MESSAGE),
    (ProductInfo.DOCKER_CONTENT_TRUST, "001", MOCK_MESSAGE),
    (ProductInfo.DOCKER_CONTENT_TRUST, "002", MOCK_MESSAGE),
    (ProductInfo.DOCKER_IMAGE_SCAN, "001", MOCK_MESSAGE),
    (ProductInfo.EXTERNAL, "001", MOCK_MESSAGE),
    (ProductInfo.EXTERNAL, "002", MOCK_MESSAGE),
    (ProductInfo.EXTERNAL, "003", MOCK_MESSAGE),
    (ProductInfo.EXTERNAL, "004", MOCK_MESSAGE),
    (ProductInfo.FORTIFY, "001", MOCK_MESSAGE),
    (ProductInfo.FORTIFY, "002", MOCK_MESSAGE),
    (ProductInfo.FORTIFY, "003", MOCK_MESSAGE),
    (ProductInfo.FORTIFY, "004", MOCK_MESSAGE),
    (ProductInfo.FORTIFY, "005", MOCK_MESSAGE),
    (
        ProductInfo.FORTIFYONDEMAND,
        "001",
        MOCK_FORTIFYONDEMAND_OPENSOURCE_GITHUB_MESSAGE,
    ),
    (ProductInfo.FORTIFYONDEMAND, "002", MOCK_FORTIFYONDEMAND_DYNAMIC_GITHUB_MESSAGE),
    (ProductInfo.FORTIFYONDEMAND, "003", MOCK_FORTIFYONDEMAND_STATIC_GITHUB_MESSAGE),
    (ProductInfo.FORTIFYONDEMAND, "004", MOCK_FORTIFYONDEMAND_GITHUB_MESSAGE),
    (ProductInfo.FORTIFYONDEMAND, "005", MOCK_FORTIFYONDEMAND_DIRECT_MESSAGE),
    (ProductInfo.NESSUS, "001", MOCK_MESSAGE),
    (ProductInfo.NEXUSIQ, "001", MOCK_MESSAGE),
    (ProductInfo.NIKTO, "001", MOCK_MESSAGE),
    (ProductInfo.NMAP, "001", MOCK_MESSAGE),
    (ProductInfo.NMAP, "002", MOCK_MESSAGE),
    (ProductInfo.OWASP, "001", MOCK_MESSAGE),
    (ProductInfo.PROWLER, "001", MOCK_MESSAGE),
    (ProductInfo.QUALYS, "001", MOCK_MESSAGE),
    (ProductInfo.QUALYS, "002", MOCK_MESSAGE),
    (ProductInfo.QUALYS, "003", MOCK_MESSAGE),
    (ProductInfo.QUALYS, "004", MOCK_MESSAGE),
    (ProductInfo.QUALYS, "005", MOCK_MESSAGE),
    (ProductInfo.QUALYS, "006", MOCK_MESSAGE),
    (ProductInfo.QUALYS, "007", MOCK_MESSAGE),
    # (ProductInfo.REAPSAW, "001", MOCK_MESSAGE),
    (ProductInfo.SCOUTSUITE, "001", MOCK_MESSAGE),
    (ProductInfo.SHIFTLEFT, "001", MOCK_MESSAGE),
    (ProductInfo.SNIPER, "001", MOCK_MESSAGE),
    (ProductInfo.SNYK, "001", MOCK_MESSAGE),
    (ProductInfo.SNYK, "002", MOCK_MESSAGE),
    (ProductInfo.SONARQUBE, "001", MOCK_MESSAGE),
    (ProductInfo.SQLMAP, "001", MOCK_MESSAGE),
    # (ProductInfo.TENABLEIO, "raw_issues.empty.json"),
    (ProductInfo.TWISTLOCK, "001", MOCK_MESSAGE),
    (ProductInfo.VERACODE, "001", MOCK_MESSAGE),
    (ProductInfo.VERACODE, "002", MOCK_MESSAGE),
    (ProductInfo.WHITESOURCE, "001", MOCK_MESSAGE),
    (ProductInfo.XRAY, "001", MOCK_MESSAGE),
    (ProductInfo.ZAP, "001", MOCK_MESSAGE),
    (ProductInfo.ZAP, "002", MOCK_MESSAGE),
    (ProductInfo.ZAP, "003", MOCK_MESSAGE),
]


@pytest.mark.parametrize(
    "product_name, input_file_name, mock_message",
    parametrized_tests_list,
)
def test_refinement(product_name, input_file_name, mock_message):
    product_name = product_name.lower().replace("-", "_")
    message = copy.deepcopy(mock_message)
    message["scenarioName"] = product_name
    message["productName"] = product_name

    file_path = os.path.join(tools_path, product_name, test_data_dir)

    with open(os.path.join(file_path, input_file_name), "rb") as f:
        target_data = f.read()

    ncis, extra_job_data, ncis_supplemental = get_refined_issues(
        CONFIG, target_data, message
    )

    ncis_issues_list = [x.to_dictionary() for x in ncis]
    expected_file_name = f"{input_file_name}_refined_issues"
    if os.getenv("TEST_REPLAY", False):
        with open(os.path.join(file_path, expected_file_name), "w") as expected:
            sorted_ncis_issues_list = sorted(ncis_issues_list, key=lambda d: d["key"])
            expected.write(
                json.dumps(sorted_ncis_issues_list, indent=4, sort_keys=True)
            )
    with open(os.path.join(file_path, expected_file_name)) as f:
        expected = json.loads(f.read())

    ncis_issues_list_json = json.loads(json.dumps(ncis_issues_list))
    diff = DeepDiff(expected, ncis_issues_list_json, ignore_order=True)
    assert not diff, "Error: refined issues do not match expected result"


@pytest.mark.parametrize(
    "product_name, input_file_name, mock_message",
    parametrized_tests_list,
)
def test_refined_fields(product_name, input_file_name, mock_message):
    product_name = product_name.lower().replace("-", "_")
    message = copy.deepcopy(mock_message)
    message["scenarioName"] = product_name
    message["productName"] = product_name

    file_path = os.path.join(tools_path, product_name, test_data_dir)

    with open(os.path.join(file_path, input_file_name), "rb") as f:
        target_data = f.read()

    ncis, extra_job_data, ncis_supplemental = get_refined_issues(
        CONFIG, target_data, message
    )

    ncis_issues_list = [x.to_dictionary() for x in ncis]
    if isinstance(ncis_issues_list, list):
        for issue in ncis_issues_list:
            issue_name = issue.get("issueName")
            key = issue.get("key")
            assert issue_name and key and "None" not in key
        assert True
    else:
        assert False
