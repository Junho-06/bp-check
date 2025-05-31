from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class CodeSeriesChecker(RuleChecker):
    def __init__(self):
        self.build_client = boto3.client("codebuild")
        self.deploy_client = boto3.client("codedeploy")

    @cached_property
    def projects(self):
        project_names = self.build_client.list_projects()["projects"]
        if not project_names:
            return []
        return self.build_client.batch_get_projects(names=project_names)["projects"]

    def codebuild_project_environment_privileged_check(self):
        compliant_resources = []
        non_compliant_resources = []

        for project in self.projects:
            if not project["environment"]["privilegedMode"]:
                compliant_resources.append(project["arn"])
            else:
                non_compliant_resources.append(project["arn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def codebuild_project_logging_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for project in self.projects:
            logs_config = project["logsConfig"]

            if (
                logs_config["cloudWatchLogs"]["status"] == "ENABLED"
                or logs_config["s3Logs"]["status"] == "ENABLED"
            ):
                compliant_resources.append(project["arn"])
            else:
                non_compliant_resources.append(project["arn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def codedeploy_auto_rollback_monitor_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        applications = self.deploy_client.list_applications()["applications"]
        for application in applications:
            deployment_group_names = self.deploy_client.list_deployment_groups(
                applicationName=application
            )["deploymentGroups"]

            if deployment_group_names == []:
                non_compliant_resources.append(application)
                continue

            deployment_groups = self.deploy_client.batch_get_deployment_groups(
                applicationName=application, deploymentGroupNames=deployment_group_names
            )["deploymentGroupsInfo"]

            for deployment_group in deployment_groups:

                if (
                    deployment_group["alarmConfiguration"]["enabled"]
                    and deployment_group["autoRollbackConfiguration"]["enabled"]
                ):
                    compliant_resources.append(deployment_group["deploymentGroupId"])
                else:
                    non_compliant_resources.append(
                        deployment_group["deploymentGroupId"]
                    )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = CodeSeriesChecker
