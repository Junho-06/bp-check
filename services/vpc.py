from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class VPCRuleChecker(RuleChecker):
    def __init__(self):
        self.ec2 = boto3.client("ec2")

    @cached_property
    def security_group_rules(self):
        return self.ec2.describe_security_group_rules()["SecurityGroupRules"]

    def ec2_transit_gateway_auto_vpc_attach_disabled(self):
        response = self.ec2.describe_transit_gateways()

        non_compliant_resources = [
            resource["TransitGatewayArn"]
            for resource in filter(
                lambda x: x["Options"]["AutoAcceptSharedAttachments"] == "enable",
                response["TransitGateways"],
            )
        ]

        compliant_resources = list(
            set(
                [
                    resource["TransitGatewayArn"]
                    for resource in response["TransitGateways"]
                ]
            )
            - set(non_compliant_resources)
        )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def restricted_ssh(self):
        non_compliant_resources = [
            f'{resource["GroupId"]} / {resource["SecurityGroupRuleId"]}'
            for resource in filter(
                lambda x: x["IsEgress"] == False
                and x["FromPort"] <= 22
                and x["ToPort"] >= 22
                and x.get("CidrIpv4") == "0.0.0.0/0",
                self.security_group_rules,
            )
        ]

        compliant_resources = list(
            set(
                [
                    f'{resource["GroupId"]} / {resource["SecurityGroupRuleId"]}'
                    for resource in self.security_group_rules
                ]
            )
            - set(non_compliant_resources)
        )
        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def restricted_common_ports(self):
        common_ports = [
            -1,  # All
            22,  # SSH
            80,  # HTTP
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            6379,  # Redis
            11211,  # Memcached
        ]

        non_compliant_resources = [
            f'{resource["GroupId"]} / {resource["SecurityGroupRuleId"]}'
            for resource in filter(
                lambda x: x["IsEgress"] == False
                and x["FromPort"] in common_ports
                and x["ToPort"] in common_ports
                and x.get("PrefixListId") is None
                and x.get("ReferencedGroupInfo") is None,
                self.security_group_rules,
            )
        ]

        compliant_resources = list(
            set(
                f'{resource["GroupId"]} / {resource["SecurityGroupRuleId"]}'
                for resource in self.security_group_rules
            )
            - set(non_compliant_resources)
        )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def subnet_auto_assign_public_ip_disabled(self):
        response = self.ec2.describe_subnets()

        non_compliant_resources = [
            resource["SubnetId"]
            for resource in filter(
                lambda x: x["MapPublicIpOnLaunch"], response["Subnets"]
            )
        ]

        compliant_resources = list(
            set(resource["SubnetId"] for resource in response["Subnets"])
            - set(non_compliant_resources)
        )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def vpc_default_security_group_closed(self):
        response = self.ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": ["default"]}]
        )

        non_compliant_resources = [
            resource["GroupId"]
            for resource in filter(
                lambda x: x["IpPermissions"] or x["IpPermissionsEgress"],
                response["SecurityGroups"],
            )
        ]

        compliant_resources = list(
            set(resource["GroupId"] for resource in response["SecurityGroups"])
            - set(non_compliant_resources)
        )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def vpc_flow_logs_enabled(self):
        response = self.ec2.describe_flow_logs()
        flow_log_enabled_vpcs = [
            resource["ResourceId"] for resource in response["FlowLogs"]
        ]

        response = self.ec2.describe_vpcs()

        non_compliant_resources = [
            resource["VpcId"]
            for resource in filter(
                lambda x: x["VpcId"] not in flow_log_enabled_vpcs, response["Vpcs"]
            )
        ]

        compliant_resources = list(
            set(resource["VpcId"] for resource in response["Vpcs"])
            - set(non_compliant_resources)
        )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def vpc_network_acl_unused_check(self):
        response = self.ec2.describe_network_acls()

        non_compliant_resources = [
            resource["NetworkAclId"]
            for resource in filter(
                lambda x: not x["Associations"], response["NetworkAcls"]
            )
        ]

        compliant_resources = list(
            set(resource["NetworkAclId"] for resource in response["NetworkAcls"])
            - set(non_compliant_resources)
        )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def vpc_peering_dns_resolution_check(self):
        response = self.ec2.describe_vpc_peering_connections()

        non_compliant_resources = [
            resource["VpcPeeringConnectionId"]
            for resource in filter(
                lambda x: x["Status"]["Code"] not in ["deleted", "deleting"]
                and (
                    not x["AccepterVpcInfo"].get("PeeringOptions")
                    or not x["AccepterVpcInfo"]["PeeringOptions"][
                        "AllowDnsResolutionFromRemoteVpc"
                    ]
                    or not x["RequesterVpcInfo"]["PeeringOptions"][
                        "AllowDnsResolutionFromRemoteVpc"
                    ]
                ),
                response["VpcPeeringConnections"],
            )
        ]

        compliant_resources = list(
            set(
                resource["VpcPeeringConnectionId"]
                for resource in response["VpcPeeringConnections"]
            )
            - set(non_compliant_resources)
        )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def vpc_sg_open_only_to_authorized_ports(self):
        authorized_port = [
            # 80
        ]

        non_compliant_resources = [
            f'{resource["GroupId"]} / {resource["SecurityGroupRuleId"]}'
            for resource in filter(
                lambda x: x["IsEgress"] == False
                and (x.get("CidrIpv4") == "0.0.0.0/0" or x.get("CidrIpv6") == "::/0")
                and x["FromPort"] not in authorized_port
                and x["ToPort"] not in authorized_port,
                self.security_group_rules,
            )
        ]

        compliant_resources = list(
            set(
                f'{resource["GroupId"]} / {resource["SecurityGroupRuleId"]}'
                for resource in self.security_group_rules
            )
            - set(non_compliant_resources)
        )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = VPCRuleChecker
