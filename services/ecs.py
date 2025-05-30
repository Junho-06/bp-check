from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class ECSRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("ecs")

    @cached_property
    def task_definitions(self):
        task_definition_arns = self.client.list_task_definitions(status="ACTIVE")[
            "taskDefinitionArns"
        ]
        latest_task_definitions = {}

        # Filter latest task definition arns
        for task_definition_arn in task_definition_arns:
            family, revision = task_definition_arn.rsplit(":", 1)
            latest_task_definitions[family] = max(
                latest_task_definitions.get(family, 0), int(revision)
            )

        # Fetch latest task definition details
        task_definitions = [
            self.client.describe_task_definition(taskDefinition=f"{family}:{revision}")[
                "taskDefinition"
            ]
            for family, revision in latest_task_definitions.items()
        ]

        return task_definitions

    @cached_property
    def clusters(self):
        cluster_arns = self.client.list_clusters()["clusterArns"]
        return self.client.describe_clusters(include=["SETTINGS"], clusters=[arn.split("/")[-1] for arn in cluster_arns])["clusters"]

    @cached_property
    def services(self):
        services = []
        for cluster in self.clusters:
            service_arns = self.client.list_services(
                cluster=cluster["clusterArn"], launchType="FARGATE"
            )["serviceArns"]
            if service_arns == []:
                continue
            services += self.client.describe_services(
                cluster=cluster["clusterArn"], services=service_arns
            )["services"]
        return services

    def ecs_awsvpc_networking_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for task_definition in self.task_definitions:
            if task_definition.get("networkMode") == "awsvpc":
                compliant_resources.append(task_definition["taskDefinitionArn"])
            else:
                non_compliant_resources.append(task_definition["taskDefinitionArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ecs_containers_nonprivileged(self):
        compliant_resources = []
        non_compliant_resources = []

        for task_definition in self.task_definitions:
            containers = task_definition["containerDefinitions"]
            privileged_containers = [
                container for container in containers if container.get("privileged")
            ]

            if privileged_containers:
                non_compliant_resources.append(task_definition["taskDefinitionArn"])
            else:
                compliant_resources.append(task_definition["taskDefinitionArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ecs_containers_readonly_access(self):
        compliant_resources = []
        non_compliant_resources = []

        for task_definition in self.task_definitions:
            containers = task_definition["containerDefinitions"]
            not_readonly_containers = [
                container
                for container in containers
                if not container.get("readonlyRootFilesystem")
            ]

            if not_readonly_containers:
                non_compliant_resources.append(task_definition["taskDefinitionArn"])
            else:
                compliant_resources.append(task_definition["taskDefinitionArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ecs_container_insights_default_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for cluster in self.clusters:
            container_insights_setting = [
                setting
                for setting in cluster["settings"]
                if setting["name"] == "containerInsights"
            ]

            if (
                container_insights_setting
                and container_insights_setting[0]["value"] == "enabled"
            ):
                compliant_resources.append(cluster["clusterArn"])
            else:
                non_compliant_resources.append(cluster["clusterArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )
    
    def ecs_container_insights_enhanced_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for cluster in self.clusters:
            container_insights_setting = [
                setting
                for setting in cluster["settings"]
                if setting["name"] == "containerInsights"
            ]

            if (
                container_insights_setting
                and container_insights_setting[0]["value"] == "enhanced"
            ):
                compliant_resources.append(cluster["clusterArn"])
            else:
                non_compliant_resources.append(cluster["clusterArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ecs_fargate_latest_platform_version(self):
        compliant_resources = []
        non_compliant_resources = []

        for service in self.services:
            if service["platformVersion"] == "LATEST":
                compliant_resources.append(service["serviceArn"])
            else:
                non_compliant_resources.append(service["serviceArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ecs_task_definition_log_configuration(self):
        compliant_resources = []
        non_compliant_resources = []

        for task_definition in self.task_definitions:
            containers = task_definition["containerDefinitions"]

            log_disabled_containers = [
                container
                for container in containers
                if "logConfiguration" not in container
            ]

            if log_disabled_containers:
                non_compliant_resources.append(task_definition["taskDefinitionArn"])
            else:
                compliant_resources.append(task_definition["taskDefinitionArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ecs_task_definition_memory_hard_limit(self):
        compliant_resources = []
        non_compliant_resources = []

        for task_definition in self.task_definitions:
            containers = task_definition["containerDefinitions"]

            containers_without_memory_limit = [
                container for container in containers if "memory" not in container
            ]

            if containers_without_memory_limit:
                non_compliant_resources.append(task_definition["taskDefinitionArn"])
            else:
                compliant_resources.append(task_definition["taskDefinitionArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def ecs_task_definition_nonroot_user(self):
        compliant_resources = []
        non_compliant_resources = []

        for task_definition in self.task_definitions:
            containers = task_definition["containerDefinitions"]

            privileged_containers = [
                container
                for container in containers
                if container.get("user") in [None, "root"]
            ]

            if privileged_containers:
                non_compliant_resources.append(task_definition["taskDefinitionArn"])
            else:
                compliant_resources.append(task_definition["taskDefinitionArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = ECSRuleChecker
