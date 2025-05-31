from models import RuleCheckResult, RuleChecker
import boto3
import json


class CloudWatchRuleChecker(RuleChecker):
    def __init__(self):
        self.client = boto3.client("cloudwatch")
        self.logs_client = boto3.client("logs")

    def cw_loggroup_retention_period_check(self):
        compliant_resources = []
        non_compliant_resources = []
        log_groups = self.logs_client.describe_log_groups()["logGroups"]

        # This rule should check if `retentionInDays` is less than n days.
        # But, instead of that, this will check if the retention setting is set to "Never expire" or not
        for log_group in log_groups:
            if "retentionInDays" in log_group:
                compliant_resources.append(log_group["logGroupArn"])
            else:
                non_compliant_resources.append(log_group["logGroupArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )
    
    def cw_loggroup_kms_encrypt_check(self):
        compliant_resources = []
        non_compliant_resources = []
        log_groups = self.logs_client.describe_log_groups()["logGroups"]

        for log_group in log_groups:
            if "kmsKeyId" in log_group:
                compliant_resources.append(log_group["logGroupArn"])
            else:
                non_compliant_resources.append(log_group["logGroupArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def cloudwatch_alarm_create_check(self):
        compliant_resources = []
        non_compliant_resources = []
        alarms = self.client.describe_alarms()["MetricAlarms"]

        if alarms == []:
            non_compliant_resources.append("No alarms were created")
        else:
            for alarm in alarms:
                compliant_resources.append(alarm["AlarmArn"])

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def cloudwatch_dashboard_create_check(self):
        compliant_resources = []
        non_compliant_resources = []
        dashboards = self.client.list_dashboards()["DashboardEntries"]

        if dashboards == []:
            non_compliant_resources.append("No Dashboards were created")
        else:
            for dashboard in dashboards:
                response = json.loads(self.client.get_dashboard(DashboardName=dashboard["DashboardName"])["DashboardBody"])
                if response["widgets"] != []:
                    compliant_resources.append(dashboard["DashboardArn"])
                else:
                    non_compliant_resources.append(f"{dashboard["DashboardName"]} dashboard has no widgets")

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = CloudWatchRuleChecker
