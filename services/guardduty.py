from models import RuleCheckResult, RuleChecker
import boto3


class GuardDutyRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("guardduty")

    def guardduty_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        response = self.client.list_detectors()["DetectorIds"]

        if response == []:
            non_compliant_resources.append("GuardDuty is disabled")
        else:
            compliant_resources.append("GuardDuty is enabled")

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )
    
    def guardduty_findings_exists(self):
        compliant_resources = []
        non_compliant_resources = []

        response = self.client.list_detectors()["DetectorIds"]

        if response == []:
            non_compliant_resources.append("GuardDuty is disabled")
        else:
            detector_id = response[0]
            findings = self.client.list_findings(DetectorId=detector_id)["FindingIds"]
            if findings == []:
                non_compliant_resources.append("GuardDuty finding is not exists")
            else:
                compliant_resources.append("GuardDuty finding is exists")

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = GuardDutyRuleChecker