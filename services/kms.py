from models import RuleCheckResult, RuleChecker
import boto3
import botocore


class KMSRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("kms")

    def cmk_backing_key_rotation_enabled(self):
        compliant_resources = []
        non_compliant_resources = []
        keys = self.client.list_keys()["Keys"]

        for key in keys:
            try:
                response = self.client.get_key_rotation_status(KeyId=key["KeyId"])
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "AccessDeniedException":
                    continue
                
            if response["KeyRotationEnabled"] == True:
                compliant_resources.append(response["KeyId"])
            else:
                non_compliant_resources.append(response["KeyId"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = KMSRuleChecker
