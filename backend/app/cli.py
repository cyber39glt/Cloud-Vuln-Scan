"""Command-line tools for developers and consultants (until the web UI exists).

python -m app.cli aws external-id
    Generate a new ExternalId for a client connection.
python -m app.cli aws validate --account-id 123456789012 --external-id <id>
    Check a client AWS connection works and is read-only.
python -m app.cli aws scan --account-id 123456789012 --external-id <id> [--regions ...] [--json]
    Run a read-only assessment and print the findings (nothing is saved to disk).
"""

import argparse
import json
import sys

from app.console import UNVERIFIED_NOTE, format_summary
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.providers.aws.errors import describe_aws_error
from app.providers.aws.session import AwsConnection, generate_external_id
from app.providers.aws.validation import validate_connection
from app.scanning import WrongAccountError, scan_aws

# ASCII markers: Windows consoles do not always display symbols such as check marks.
_MARKERS = {"ok": "[ OK ]", "failed": "[FAIL]", "skipped": "[SKIP]"}


def _aws_external_id(_: argparse.Namespace) -> int:
    print(generate_external_id(get_settings().consultancy_name))
    return 0


def _connection(args: argparse.Namespace) -> AwsConnection | None:
    try:
        return AwsConnection(
            account_id=args.account_id,
            external_id=args.external_id,
            role_name=get_settings().aws_assessment_role_name,
        )
    except ValueError as exc:
        print(f"Invalid input: {exc}")
        return None


def _aws_validate(args: argparse.Namespace) -> int:
    settings = get_settings()
    connection = _connection(args)
    if connection is None:
        return 2

    print(f"Validating AWS account {connection.account_id} via {connection.role_arn}\n")
    report = validate_connection(connection, settings)
    for check in report.checks:
        detail = f"  {check.detail}" if check.detail else ""
        print(f"{_MARKERS[check.status]} {check.name}{detail}")
    print("\nConnection is ready." if report.ok else "\nConnection is NOT ready.")
    return 0 if report.ok else 1


def _aws_scan(args: argparse.Namespace) -> int:
    settings = get_settings()
    connection = _connection(args)
    if connection is None:
        return 2
    regions = [r.strip() for r in args.regions.split(",") if r.strip()] if args.regions else None

    if not args.json:
        scope = ", ".join(regions) if regions else "all enabled regions"
        print(f"Assessing AWS account {connection.account_id} ({scope}). Read-only.")
    try:
        result = scan_aws(connection, settings, regions=regions)
    except WrongAccountError as exc:
        print(f"Stopped before collecting anything: {exc}")
        return 1
    except Exception as exc:
        problem = describe_aws_error(exc)
        print(f"Scan failed: {problem.message} {problem.hint}".strip())
        print("Tip: run 'aws validate' with the same values to diagnose.")
        return 1

    if args.json:
        print(json.dumps(result.model_dump(mode="json"), indent=2))
    else:
        print(format_summary(result))
        print(f"\n{UNVERIFIED_NOTE}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__.splitlines()[0])
    providers = parser.add_subparsers(dest="provider", required=True)

    aws = providers.add_parser("aws", help="AWS connection and assessment tools")
    aws_commands = aws.add_subparsers(dest="command", required=True)
    aws_commands.add_parser("external-id", help="generate an ExternalId").set_defaults(
        handler=_aws_external_id
    )
    validate = aws_commands.add_parser("validate", help="validate a client connection")
    validate.add_argument("--account-id", required=True, help="client AWS account ID (12 digits)")
    validate.add_argument("--external-id", required=True, help="ExternalId for this client")
    validate.set_defaults(handler=_aws_validate)

    scan = aws_commands.add_parser("scan", help="run a read-only assessment")
    scan.add_argument("--account-id", required=True, help="client AWS account ID (12 digits)")
    scan.add_argument("--external-id", required=True, help="ExternalId for this client")
    scan.add_argument("--regions", help="comma-separated regions in scope (default: all enabled)")
    scan.add_argument("--json", action="store_true", help="print the full dataset as JSON")
    scan.set_defaults(handler=_aws_scan)

    args = parser.parse_args(argv)
    # Keep JSON logs quiet in a terminal session; errors still show.
    configure_logging("WARNING")
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
