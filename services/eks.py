from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class EKSRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("eks")

    @cached_property
    def clusters(self):
        cluster_names = self.client.list_clusters()["clusters"]
        return [
            self.client.describe_cluster(name=cluster_name)["cluster"]
            for cluster_name in cluster_names
        ]

    def eks_cluster_logging_enabled(self):
        compliant_resource = []
        non_compliant_resources = []

        for cluster in self.clusters:
            if (
                cluster["logging"]["clusterLogging"][0]["enabled"]
                and len(cluster["logging"]["clusterLogging"][0]["types"]) == 5
            ):
                compliant_resource.append(cluster["arn"])
            else:
                non_compliant_resources.append(cluster["arn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def eks_cluster_secrets_encrypted(self):
        compliant_resource = []
        non_compliant_resources = []

        for cluster in self.clusters:
            if (
                "encryptionConfig" in cluster
                and "secrets" in cluster["encryptionConfig"][0]["resources"]
            ):
                compliant_resource.append(cluster["arn"])
            else:
                non_compliant_resources.append(cluster["arn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def eks_endpoint_no_public_access(self):
        compliant_resource = []
        non_compliant_resources = []

        for cluster in self.clusters:
            if cluster["resourcesVpcConfig"]["endpointPublicAccess"]:
                non_compliant_resources.append(cluster["arn"])
            else:
                compliant_resource.append(cluster["arn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )
    
    def eks_cluster_latest_version(self):
        compliant_resource = []
        non_compliant_resources = []

        latest_version = self.client.describe_cluster_versions()["clusterVersions"][0]["clusterVersion"]
        for cluster in self.clusters:
            if cluster["version"] == latest_version:
                compliant_resource.append(cluster["arn"])
            else:
                non_compliant_resources.append(cluster["arn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = EKSRuleChecker
