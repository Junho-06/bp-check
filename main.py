from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import argparse

from InquirerLib import prompt
from InquirerLib.InquirerPy.utils import InquirerPyKeybindings
from InquirerLib.InquirerPy.base import Choice
from colorama import Style, Fore

from utils import *
import services


prompt_key_bindings: InquirerPyKeybindings = {
    "toggle-all-true": [{"key": "a"}],
    "toggle-all-false": [{"key": "A"}],
    "toggle-all": [{"key": "i"}],
}


def get_command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--level",
        help="Only perform checks if level <= rule_level. Default: 1",
        type=int,
        choices=[1, 2],
        default=1,
    )
    parser.add_argument(
        "--ruleset", help="Use predefined bp rule sets. Please provide filename."
    )
    parser.add_argument(
        "--show-all",
        help="Show all resources including compliant one.",
        action="store_true",
    )
    return parser.parse_args()


def ask_services_to_enable(bp):
    cli_questions = [
        {
            "type": "checkbox",
            "message": "Select AWS Services to inspect.",
            "name": "services",
            "choices": [
                Choice(service_name, enabled=bool(v["enabled"]))
                for service_name, v in bp.items()
            ],
        }
    ]

    answers = prompt(questions=cli_questions, keybindings=prompt_key_bindings)
    for service in bp.keys():
        bp[service]["enabled"] = service in answers["services"]
    return bp


def perform_bp_rules_check(bp, level=2):
    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(_rule_check, service_name, service, level)
            for service_name, service in bp.items()
        ]

        [future.result() for future in futures]
    return bp


def _rule_check(service_name, service, level):
    now = datetime.now()

    if not service["enabled"]:
        return
    if service_name == "Lambda":
        service_name = "_lambda"

    rule_checker = getattr(services, convert_snake_case(service_name)).rule_checker()
    for rule_name, rule in service["rules"].items():
        if not rule["enabled"] or rule["level"] < level:
            continue
        rule["result"] = rule_checker.check_rule(convert_snake_case(rule_name))

    elapsed_time = datetime.now() - now
    print(f"{convert_snake_case(service_name)} - Processing Time: {elapsed_time.total_seconds()}")


def show_bp_result(bp, level=2, show_all=False, excluded_resources={}):
    for service_name, service in bp.items():
        if not service["enabled"]:
            continue
        print(f"{'=' * 25} {service_name + ' ':=<30}")

        for rule_name, rule in service["rules"].items():
            if not rule["enabled"] or rule["level"] < level:
                continue

            if rule["result"].passed:
                style = Style.DIM
                color = Fore.GREEN
                mark = "✅"
            elif rule["level"] == 2 and not rule["result"].passed:
                style = Style.BRIGHT
                color = Fore.RED
                mark = "❌"
            elif rule["level"] == 1 and not rule["result"].passed:
                style = Style.NORMAL
                color = Fore.LIGHTRED_EX
                mark = "❕"

            print(f"{style}{rule_name:50}{Style.RESET_ALL} - {color}{mark}{Fore.RESET}")
            if show_all:
                for resource in rule["result"].compliant_resources:
                    print(f"    - {Style.DIM}{resource}{Style.RESET_ALL}")
            for resource in rule["result"].non_compliant_resources:
                if excluded_resources.get(resource) in [rule_name, "all"]:
                    print(f"    - {Style.DIM}{resource}{Style.RESET_ALL}")
                else:
                    print(f"    - {color}{resource}{Fore.RESET}")

        print()


if __name__ == "__main__":
    args = get_command_line_args()

    excluded_resources = parse_excluded_resources()

    bp = load_bp_from_file(default_ruleset=args.ruleset)
    bp = ask_services_to_enable(bp)
    save_bp_to_file(bp)

    bp = perform_bp_rules_check(bp, level=args.level)
    show_bp_result(
        bp,
        level=args.level,
        show_all=args.show_all,
        excluded_resources=excluded_resources,
    )
