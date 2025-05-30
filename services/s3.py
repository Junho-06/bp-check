from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3
import botocore.exceptions


class S3RuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("s3")
        self.sts_client = boto3.client("sts")
        self.s3control_client = boto3.client("s3control")
        self.backup_client = boto3.client("backup")

    @cached_property
    def account_id(self):
        return self.sts_client.get_caller_identity().get("Account")

    @cached_property
    def buckets(self):
        return self.client.list_buckets()["Buckets"]

    def s3_access_point_in_vpc_only(self):
        compliant_resources = []
        non_compliant_resources = []

        access_points = self.s3control_client.list_access_points(
            AccountId=self.account_id
        )["AccessPointList"]
        for access_point in access_points:
            if access_point["NetworkOrigin"] == "VPC":
                compliant_resources.append(access_point["AccessPointArn"])
            else:
                non_compliant_resources.append(access_point["AccessPointArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def s3_bucket_default_lock_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for bucket in self.buckets:
            try:
                response = self.client.get_object_lock_configuration(
                    Bucket=bucket["Name"]
                )
                compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")
            except botocore.exceptions.ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "ObjectLockConfigurationNotFoundError"
                ):
                    non_compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")
                else:
                    raise e

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def s3_bucket_level_public_access_prohibited(self):
        compliant_resources = []
        non_compliant_resources = []

        for bucket in self.buckets:
            response = self.client.get_public_access_block(Bucket=bucket["Name"])
            if False not in response["PublicAccessBlockConfiguration"].values():
                compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")
            else:
                non_compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def s3_bucket_logging_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for bucket in self.buckets:
            response = self.client.get_bucket_logging(Bucket=bucket["Name"])
            if "LoggingEnabled" in response:
                compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")
            else:
                non_compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def s3_bucket_ssl_requests_only(self):
        compliant_resources = []
        non_compliant_resources = []
        
        for bucket in self.buckets:
            try:
                policy = self.client.get_bucket_policy(Bucket=bucket["Name"])["Policy"]
            except botocore.exceptions.ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "NoSuchBucketPolicy"
                ):
                    continue
                else:
                    raise e
            if "aws:SecureTransport" in policy:
                compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")
            else:
                non_compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def s3_bucket_versioning_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for bucket in self.buckets:
            response = self.client.get_bucket_versioning(Bucket=bucket["Name"])
            if "Status" in response and response["Status"] == "Enabled":
                compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")
            else:
                non_compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def s3_default_encryption_kms(self):
        compliant_resources = []
        non_compliant_resources = []

        for bucket in self.buckets:
            configuration = self.client.get_bucket_encryption(Bucket=bucket["Name"])[
                "ServerSideEncryptionConfiguration"
            ]

            if (
                configuration["Rules"][0]["ApplyServerSideEncryptionByDefault"][
                    "SSEAlgorithm"
                ]
                == "aws:kms"
            ):
                compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")
            else:
                non_compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def s3_event_notifications_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for bucket in self.buckets:
            configuration = self.client.get_bucket_notification_configuration(
                Bucket=bucket["Name"]
            )
            if (
                "LambdaFunctionConfigurations" in configuration
                or "QueueConfigurations" in configuration
                or "TopicConfigurations" in configuration
            ):
                compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")
            else:
                non_compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def s3_last_backup_recovery_point_created(self):
        compliant_resources = []
        non_compliant_resources = []

        for bucket in self.buckets:
            backups = self.backup_client.list_recovery_points_by_resource(
                ResourceArn=f"arn:aws:s3:::{bucket['Name']}",
                ManagedByAWSBackupOnly=False,
                MaxResults = 100
            )

            if backups["RecoveryPoints"] != []:
                compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")
            else:
                non_compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def s3_lifecycle_policy_check(self):
        compliant_resources = []
        non_compliant_resources = []

        for bucket in self.buckets:
            try:
                configuration = self.client.get_bucket_lifecycle_configuration(
                    Bucket=bucket["Name"]
                )
                compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
                    non_compliant_resources.append(f"arn:aws:s3:::{bucket['Name']}")
                else:
                    raise e

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = S3RuleChecker
