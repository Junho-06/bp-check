from models import RuleCheckResult, RuleChecker
from functools import cached_property
from datetime import datetime, timedelta
from dateutil.tz import tzlocal
import boto3


class DynamoDBRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("dynamodb")
        self.backup_client = boto3.client("backup")
        self.autoscaling_client = boto3.client("application-autoscaling")

    @cached_property
    def tables(self):
        table_names = self.client.list_tables()["TableNames"]
        return [
            self.client.describe_table(TableName=table_name)["Table"]
            for table_name in table_names
        ]

    def dynamodb_autoscaling_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for table in self.tables:
            if (
                table.get("BillingModeSummary", {}).get("BillingMode")
                == "PAY_PER_REQUEST"
            ):
                compliant_resources.append(table["TableArn"])
                continue

            scaling_policies = self.autoscaling_client.describe_scaling_policies(
                ServiceNamespace="dynamodb", ResourceId=f"table/{table['TableName']}"
            )["ScalingPolicies"]
            scaling_policy_dimensions = [
                policy["ScalableDimension"] for policy in scaling_policies
            ]

            if (
                "dynamodb:table:ReadCapacityUnits" in scaling_policy_dimensions
                and "dynamodb:table:WriteCapacityUnits" in scaling_policy_dimensions
            ):
                compliant_resources.append(table["TableArn"])
            else:
                non_compliant_resources.append(table["TableArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def dynamodb_last_backup_recovery_point_created(self):
        compliant_resources = []
        non_compliant_resources = []

        for table in self.tables:
            recovery_points = self.backup_client.list_recovery_points_by_resource(
                ResourceArn=table["TableArn"]
            )["RecoveryPoints"]
            if not recovery_points:
                non_compliant_resources.append(table["TableArn"])
                continue

            latest_recovery_point = sorted(
                [recovery_point["CreationDate"] for recovery_point in recovery_points]
            )[-1]

            if datetime.now(tz=tzlocal()) - latest_recovery_point > timedelta(days=1):
                non_compliant_resources.append(table["TableArn"])
            else:
                compliant_resources.append(table["TableArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def dynamodb_pitr_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for table in self.tables:
            backup = self.client.describe_continuous_backups(
                TableName=table["TableName"]
            )["ContinuousBackupsDescription"]

            if (
                backup["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]
                == "ENABLED"
            ):
                compliant_resources.append(table["TableArn"])
            else:
                non_compliant_resources.append(table["TableArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def dynamodb_table_deletion_protection_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for table in self.tables:
            if table["DeletionProtectionEnabled"] == True:
                compliant_resources.append(table["TableArn"])
            else:
                non_compliant_resources.append(table["TableArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def dynamodb_table_encrypted_kms(self):
        compliant_resources = []
        non_compliant_resources = []

        for table in self.tables:
            if (
                "SSEDescription" in table
                and table["SSEDescription"]["Status"] == "ENABLED"
                and table["SSEDescription"]["SSEType"] == "KMS"
            ):
                compliant_resources.append(table["TableArn"])
            else:
                non_compliant_resources.append(table["TableArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = DynamoDBRuleChecker
