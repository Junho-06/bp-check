from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class CloudFrontRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("cloudfront")

    @cached_property
    def distributions(self):
        return self.client.list_distributions()["DistributionList"].get("Items", [])

    @cached_property
    def distribution_details(self):
        responses = [
            self.client.get_distribution(Id=distribution["Id"])["Distribution"]
            for distribution in self.distributions
        ]
        return {
            distribution["Id"]: response
            for distribution, response in zip(self.distributions, responses)
        }

    def cloudfront_accesslogs_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for distribution in self.distributions:
            distribution = self.distribution_details[distribution["Id"]]
            if (
                "Logging" in distribution["DistributionConfig"]
                and distribution["DistributionConfig"]["Logging"]["Enabled"] == True
            ):
                compliant_resources.append(distribution["ARN"])
            else:
                non_compliant_resources.append(distribution["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def cloudfront_associated_with_waf(self):
        compliant_resources = []
        non_compliant_resources = []

        for distribution in self.distributions:
            if "WebACLId" in distribution and distribution["WebACLId"] != "":
                compliant_resources.append(distribution["ARN"])
            else:
                non_compliant_resources.append(distribution["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def cloudfront_default_root_object_configured(self):
        compliant_resources = []
        non_compliant_resources = []

        for distribution in self.distributions:
            distribution = self.distribution_details[distribution["Id"]]

            if distribution["DistributionConfig"]["DefaultRootObject"] != "":
                compliant_resources.append(distribution["ARN"])
            else:
                non_compliant_resources.append(distribution["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def cloudfront_no_deprecated_ssl_protocols(self):
        compliant_resources = []
        non_compliant_resources = []

        for distribution in self.distributions:
            for origin in distribution["Origins"]["Items"]:
                if (
                    "CustomOriginConfig" in origin
                    and origin["CustomOriginConfig"]["OriginProtocolPolicy"]
                    in ["https-only", "match-viewer"]
                    and "SSLv3"
                    in origin["CustomOriginConfig"]["OriginSslProtocols"]["Items"]
                ):

                    non_compliant_resources.append(distribution["ARN"])
                    break
            else:
                compliant_resources.append(distribution["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def cloudfront_s3_origin_access_control_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for distribution in self.distributions:
            for origin in distribution["Origins"]["Items"]:
                if "S3OriginConfig" in origin and origin["OriginAccessControlId"] == "":
                    non_compliant_resources.append(distribution["ARN"])
                    break
            else:
                compliant_resources.append(distribution["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def cloudfront_viewer_policy_https(self):
        compliant_resources = []
        non_compliant_resources = []

        for distribution in self.distributions:
            if (
                distribution["DefaultCacheBehavior"]["ViewerProtocolPolicy"]
                == "allow-all"
            ):
                non_compliant_resources.append(distribution["ARN"])
                continue

            if "Items" in distribution["CacheBehaviors"]:
                allow_alls = [
                    behavior
                    for behavior in distribution["CacheBehaviors"]["Items"]
                    if behavior["ViewerProtocolPolicy"] == "allow-all"
                ]
                if allow_alls:
                    non_compliant_resources.append(distribution["ARN"])
                    continue

            compliant_resources.append(distribution["ARN"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = CloudFrontRuleChecker
