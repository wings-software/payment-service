import copy

MOCK_MESSAGE = {
    "scenarioName": "checkmarx",
    "productName": "checkmarx",
    "policyName": "policy with upload",
    "jobId": "7208394414039548170",
    "policyId": "3507742950716442876",
    "customerId": "4503657098653210424",
    "targetId": "Mq07z7LFR7qxrJON18125g",
    "targetName": "Custom Target virtual url",
    "scenarioId": "8207742350716442876",
    "currentRuntime": 1536070894,
    "permanentRunOptions": {},
    "environmentType": {},
}

MOCK_FORTIFYONDEMAND_OPENSOURCE_GITHUB_MESSAGE = copy.deepcopy(MOCK_MESSAGE)
MOCK_FORTIFYONDEMAND_OPENSOURCE_GITHUB_MESSAGE.update(
    {
        "permanentRunOptions": {"fortifyOnDemandScanTypeOption": "OpenSource"},
        "environmentType": "github",
    }
)
MOCK_FORTIFYONDEMAND_DYNAMIC_GITHUB_MESSAGE = copy.deepcopy(MOCK_MESSAGE)
MOCK_FORTIFYONDEMAND_DYNAMIC_GITHUB_MESSAGE.update(
    {
        "permanentRunOptions": {"fortifyOnDemandScanTypeOption": "Dynamic"},
        "environmentType": "github",
    }
)
MOCK_FORTIFYONDEMAND_STATIC_GITHUB_MESSAGE = copy.deepcopy(MOCK_MESSAGE)
MOCK_FORTIFYONDEMAND_STATIC_GITHUB_MESSAGE.update(
    {
        "permanentRunOptions": {"fortifyOnDemandScanTypeOption": "Static"},
        "environmentType": "github",
    }
)
MOCK_FORTIFYONDEMAND_GITHUB_MESSAGE = copy.deepcopy(MOCK_MESSAGE)
MOCK_FORTIFYONDEMAND_GITHUB_MESSAGE.update(
    {
        "permanentRunOptions": {"fortifyOnDemandScanTypeOption": None},
        "environmentType": "github",
    }
)
MOCK_FORTIFYONDEMAND_DIRECT_MESSAGE = copy.deepcopy(MOCK_MESSAGE)
MOCK_FORTIFYONDEMAND_DIRECT_MESSAGE.update(
    {
        "permanentRunOptions": {"fortifyOnDemandScanTypeOption": None},
        "environmentType": "direct",
    }
)
