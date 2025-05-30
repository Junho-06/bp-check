from models import RuleCheckResult, RuleChecker
from functools import cached_property
import datetime
from dateutil.tz import tzlocal
import boto3


class RDSRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("rds")
        self.backup_client = boto3.client("backup")
        self.ec2_client = boto3.client("ec2")

    @cached_property
    def db_clusters(self):
        return self.client.describe_db_clusters()["DBClusters"]

    @cached_property
    def db_instances(self):
        return self.client.describe_db_instances()["DBInstances"]

    def aurora_last_backup_recovery_point_created(self):
        compliant_resources = []
        non_compliant_resources = []

        clusters = self.db_clusters
        for cluster in clusters:
            recovery_points = self.backup_client.list_recovery_points_by_resource(
                ResourceArn=cluster["DBClusterArn"]
            )["RecoveryPoints"]
            recovery_point_creation_dates = sorted(
                [i["CreationDate"] for i in recovery_points]
            )
            if datetime.datetime.now(tz=tzlocal()) - recovery_point_creation_dates[
                -1
            ] < datetime.timedelta(days=1):
                compliant_resources.append(cluster["DBClusterArn"])
            else:
                non_compliant_resources.append(cluster["DBClusterArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def aurora_mysql_backtracking_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        clusters = self.db_clusters
        for cluster in clusters:
            if (
                cluster["Engine"] == "aurora-mysql"
                and cluster.get("EarliestBacktrackTime", None) == None
            ):
                non_compliant_resources.append(cluster["DBClusterArn"])
            else:
                compliant_resources.append(cluster["DBClusterArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def db_cluster_auto_backup_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        clusters = self.db_clusters
        for cluster in clusters:
            if cluster.get("BackupRetentionPeriod", 0) > 0:
                compliant_resources.append(cluster["DBClusterArn"])
            else:
                non_compliant_resources.append(cluster["DBClusterArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def rds_cluster_auto_minor_version_upgrade_enable(self):
        compliant_resources = []
        non_compliant_resources = []

        clusters = self.db_clusters
        for cluster in clusters:
            if cluster["Engine"] == "docdb" or cluster.get("AutoMinorVersionUpgrade"):
                compliant_resources.append(cluster["DBClusterArn"])
            else:
                non_compliant_resources.append(cluster["DBClusterArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def rds_cluster_default_admin_check(self):
        compliant_resources = []
        non_compliant_resources = []

        clusters = self.db_clusters
        for cluster in clusters:
            if cluster["MasterUsername"] not in ["admin", "postgres"]:
                compliant_resources.append(cluster["DBClusterArn"])
            else:
                non_compliant_resources.append(cluster["DBClusterArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def rds_cluster_deletion_protection_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        clusters = self.db_clusters
        for cluster in clusters:
            if cluster["DeletionProtection"]:
                compliant_resources.append(cluster["DBClusterArn"])
            else:
                non_compliant_resources.append(cluster["DBClusterArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def rds_cluster_encrypted_at_rest(self):
        compliant_resources = []
        non_compliant_resources = []

        clusters = self.db_clusters
        for cluster in clusters:
            if cluster["StorageEncrypted"]:
                compliant_resources.append(cluster["DBClusterArn"])
            else:
                non_compliant_resources.append(cluster["DBClusterArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def rds_cluster_iam_authentication_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        clusters = self.db_clusters
        for cluster in clusters:
            if cluster["Engine"] == "docdb" or cluster.get(
                "IAMDatabaseAuthenticationEnabled"
            ):
                compliant_resources.append(cluster["DBClusterArn"])
            else:
                non_compliant_resources.append(cluster["DBClusterArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def rds_cluster_multi_az_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        clusters = self.db_clusters
        for cluster in clusters:
            if len(cluster.get("AvailabilityZones", [])) > 1:
                compliant_resources.append(cluster["DBClusterArn"])
            else:
                non_compliant_resources.append(cluster["DBClusterArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def rds_db_security_group_not_allowed(self):
        compliant_resources = []
        non_compliant_resources = []

        clusters = self.db_clusters
        security_groups = self.ec2_client.describe_security_groups()["SecurityGroups"]
        default_security_group_ids = [
            i["GroupId"] for i in security_groups if i["GroupName"] == "default"
        ]

        for cluster in clusters:
            db_security_groups = [
                i["VpcSecurityGroupId"]
                for i in cluster["VpcSecurityGroups"]
                if i["Status"] == "active"
            ]

            for default_security_group_id in default_security_group_ids:
                if default_security_group_id in db_security_groups:
                    non_compliant_resources.append(cluster["DBClusterArn"])
                    break
            else:
                compliant_resources.append(cluster["DBClusterArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def rds_enhanced_monitoring_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        instances = self.db_instances
        for instance in instances:
            if instance.get("MonitoringInterval", 0):
                compliant_resources.append(instance["DBInstanceArn"])
            else:
                non_compliant_resources.append(instance["DBInstanceArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def rds_instance_public_access_check(self):
        compliant_resources = []
        non_compliant_resources = []

        instances = self.db_instances
        for instance in instances:
            if instance["PubliclyAccessible"]:
                non_compliant_resources.append(instance["DBInstanceArn"])
            else:
                compliant_resources.append(instance["DBInstanceArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def rds_logging_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        clusters = self.db_clusters
        logs_for_engine = {
            "aurora-mysql": ["audit", "error", "general", "slowquery"],
            "aurora-postgresql": ["postgresql"],
            "docdb": ["audit", "profiler"],
        }

        for cluster in clusters:
            if sorted(cluster["EnabledCloudwatchLogsExports"]) == logs_for_engine.get(
                cluster["Engine"]
            ):
                compliant_resources.append(cluster["DBClusterArn"])
            else:
                non_compliant_resources.append(cluster["DBClusterArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def rds_snapshot_encrypted(self):
        compliant_resources = []
        non_compliant_resources = []

        cluster_snapshots = self.client.describe_db_cluster_snapshots()[
            "DBClusterSnapshots"
        ]

        for snapshot in cluster_snapshots:
            if snapshot.get("StorageEncrypted") == True:
                compliant_resources.append(snapshot["DBClusterSnapshotArn"])
            else:
                non_compliant_resources.append(snapshot["DBClusterSnapshotArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = RDSRuleChecker
