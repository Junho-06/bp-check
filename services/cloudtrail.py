from models import RuleCheckResult, RuleChecker
import boto3


class CloudTrailRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("cloudtrail")

    def trail_create_check(self):
        compliant_resources = []
        non_compliant_resources = []

        current_region = boto3.session.Session().region_name
        trails = self.client.list_trails()["Trails"]

        if trails == []:
            non_compliant_resources.append("No Trails were created")
        else:
            for trail in trails:
                if trail["HomeRegion"] == current_region:
                    compliant_resources.append(trail["TrailARN"])
            if compliant_resources == []:
                non_compliant_resources.append("No Trails were created")

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = CloudTrailRuleChecker