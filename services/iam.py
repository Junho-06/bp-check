from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class IAMRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("iam")

    @cached_property
    def policies(self):
        return self.client.list_policies(Scope="Local")["Policies"]
    
    @cached_property
    def managed_policies(self):
        return self.client.list_policies(Scope="AWS")["Policies"]

    @cached_property
    def policy_default_versions(self):
        responses = [
            self.client.get_policy_version(
                PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
            )["PolicyVersion"]
            for policy in self.policies
        ]

        return {
            policy["Arn"]: response
            for policy, response in zip(self.policies, responses)
        }

    def iam_policy_no_statements_with_admin_access(self):
        compliant_resource = []
        non_compliant_resources = []

        for policy in self.policies:
            policy_version = self.policy_default_versions[policy["Arn"]]

            for statement in policy_version["Document"]["Statement"]:
                if "Action" in statement and "Resource" in statement:
                    if (
                        statement["Action"] == "*"
                        and statement["Resource"] == "*"
                        and statement["Effect"] == "Allow"
                    ):
                        non_compliant_resources.append(policy["Arn"])
                        break
            else:
                compliant_resource.append(policy["Arn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def iam_policy_no_statements_with_full_access(self):
        compliant_resource = []
        non_compliant_resources = []

        for policy in self.policies:
            policy_version = self.policy_default_versions[policy["Arn"]]

            for statement in policy_version["Document"]["Statement"]:
                if statement["Effect"] == "Deny":
                    continue

                if "Action" in statement and "Resource" in statement:
                    if type(statement["Action"]) == str:
                        statement["Action"] = [statement["Action"]]

                    full_access_actions = [
                        action for action in statement["Action"] if action.endswith(":*")
                    ]
                    if full_access_actions:
                        non_compliant_resources.append(policy["Arn"])
                        break
            else:
                compliant_resource.append(policy["Arn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )

    def iam_role_managed_policy_check(self):
        compliant_resource = []
        non_compliant_resources = []

        for policy in self.managed_policies:
            if (
                policy["AttachmentCount"] > 0
            ):
                compliant_resource.append(policy["Arn"])
            else:
                non_compliant_resources.append(policy["Arn"])

        return RuleCheckResult(
            passed=not compliant_resource,
            compliant_resources=compliant_resource,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = IAMRuleChecker
