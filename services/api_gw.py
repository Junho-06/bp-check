from models import RuleCheckResult, RuleChecker
from functools import cached_property
import boto3


class APIGatewayRuleChecker(RuleChecker):
    def __init__(self):
        self.v1_client = boto3.client("apigateway")
        self.v2_client = boto3.client("apigatewayv2")

    @cached_property
    def http_apis(self):
        return self.v2_client.get_apis()["Items"]

    @cached_property
    def rest_apis(self):
        return self.v1_client.get_rest_apis()["items"]

    @cached_property
    def rest_api_stages(self):
        responses = [
            self.v1_client.get_stages(
                restApiId=api["id"],
            )
            for api in self.rest_apis
        ]
        return {api["id"]: response for api, response in zip(self.rest_apis, responses)}

    def api_gwv2_access_logs_enabled(self):
        compliant_resources = []
        non_compliant_resources = []

        for api in self.http_apis:
            stages = self.v2_client.get_stages(
                ApiId=api["ApiId"],
            )

            if stages["Items"] == []:
                non_compliant_resources.append(api["Name"])

            non_compliant_resources += [
                f"{api['Name']} / {stage['StageName']}"
                for stage in stages["Items"]
                if "AccessLogSettings" not in stage
            ]

            compliant_resources += list(
                set(
                    [
                        f"{api['Name']} / {stage['StageName']}"
                        for stage in stages["Items"]
                    ]
                )
                - set(non_compliant_resources)
            )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def api_gwv2_authorization_type_configured(self):
        compliant_resources = []
        non_compliant_resources = []

        for api in self.http_apis:
            response = self.v2_client.get_routes(
                ApiId=api["ApiId"],
            )

            if response["Items"] == []:
                non_compliant_resources.append(api["Name"])

            non_compliant_resources += [
                f"{api['Name']} / {route['RouteKey']}"
                for route in response["Items"]
                if route["AuthorizationType"] == "NONE"
            ]

            compliant_resources += list(
                set(
                    [
                        f"{api['Name']} / {route['RouteKey']}"
                        for route in response["Items"]
                    ]
                )
                - set(non_compliant_resources)
            )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def api_gw_associated_with_waf(self):
        compliant_resources = []
        non_compliant_resources = []

        for api in self.rest_apis:
            stages = self.rest_api_stages[api["id"]]

            for stage in stages["item"]:
                stage_arn = f"arn:aws:apigateway:{self.v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"

                if "webAclArn" in stage:
                    compliant_resources.append(stage_arn)
                else:
                    non_compliant_resources.append(stage_arn)

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def api_gw_cache_enabled_and_encrypted(self):
        compliant_resources = []
        non_compliant_resources = []

        for api in self.rest_apis:
            stages = self.rest_api_stages[api["id"]]

            non_compliant_resources += [
                f"arn:aws:apigateway:{self.v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                for stage in stages["item"]
                if not "*/*" in stage["methodSettings"]
                or (
                    not stage["methodSettings"]["*/*"]["cachingEnabled"]
                    or not stage["methodSettings"]["*/*"]["cacheDataEncrypted"]
                )
            ]
            compliant_resources += list(
                set(
                    [
                        f"arn:aws:apigateway:{self.v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                        for stage in stages["item"]
                    ]
                )
                - set(non_compliant_resources)
            )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def api_gw_execution_logging_enabled(self):
        compliant_resources = []
        non_compliant_resources = []
        for api in self.rest_apis:
            stages = self.rest_api_stages[api["id"]]

            non_compliant_resources += [
                f"arn:aws:apigateway:{self.v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                for stage in stages["item"]
                if not "*/*" in stage["methodSettings"]
                or (
                    not "loggingLevel" in stage["methodSettings"]["*/*"]
                    or stage["methodSettings"]["*/*"]["loggingLevel"] == "OFF"
                )
            ]
            compliant_resources += list(
                set(
                    [
                        f"arn:aws:apigateway:{self.v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                        for stage in stages["item"]
                    ]
                )
                - set(non_compliant_resources)
            )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )

    def api_gw_xray_enabled(self):
        compliant_resources = []
        non_compliant_resources = []
        for api in self.rest_apis:
            stages = self.rest_api_stages[api["id"]]

            non_compliant_resources += [
                f"arn:aws:apigateway:{self.v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                for stage in stages["item"]
                if not stage["tracingEnabled"]
            ]
            compliant_resources += list(
                set(
                    [
                        f"arn:aws:apigateway:{self.v1_client.meta.region_name}::/restapis/{api['id']}/stages/{stage['stageName']}"
                        for stage in stages["item"]
                    ]
                )
                - set(non_compliant_resources)
            )

        return RuleCheckResult(
            passed=not non_compliant_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
        )


rule_checker = APIGatewayRuleChecker
