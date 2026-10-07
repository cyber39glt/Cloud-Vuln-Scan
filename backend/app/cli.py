"""Command-line tools for developers and consultants (until the web UI exists).

python -m app.cli aws external-id
    Generate a new ExternalId for a client connection.
python -m app.cli aws validate --account-id 123456789012 --external-id <id>
    Check a client AWS connection works and is read-only.
"""

import argparse
import sys

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.providers.aws.session import AwsConnection, generate_external_id
from app.providers.aws.validation import validate_connection

# ASCII markers: Windows consoles do not always display symbols such as check marks.
_MARKERS = {"ok": "[ OK ]", "failed": "[FAIL]", "skipped": "[SKIP]"}


def _aws_external_id(_: argparse.Namespace) -> int:
    print(generate_external_id(get_settings().consultancy_name))
    return 0


def _aws_validate(args: argparse.Namespace) -> int:
    settings = get_settings()
    try:
        connection = AwsConnection(
            account_id=args.account_id,
            external_id=args.external_id,
            role_name=settings.aws_assessment_role_name,
        )
    except ValueError as exc:
        print(f"Invalid input: {exc}")
        return 2

    print(f"Validating AWS account {connection.account_id} via {connection.role_arn}\n")
    report = validate_connection(connection, settings)
    for check in report.checks:
        detail = f"  {check.detail}" if check.detail else ""
        print(f"{_MARKERS[check.status]} {check.name}{detail}")
    print("\nConnection is ready." if report.ok else "\nConnection is NOT ready.")
    return 0 if report.ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__.splitlines()[0])
    providers = parser.add_subparsers(dest="provider", required=True)

    aws = providers.add_parser("aws", help="AWS connection tools")
    aws_commands = aws.add_subparsers(dest="command", required=True)
    aws_commands.add_parser("external-id", help="generate an ExternalId").set_defaults(
        handler=_aws_external_id
    )
    validate = aws_commands.add_parser("validate", help="validate a client connection")
    validate.add_argument("--account-id", required=True, help="client AWS account ID (12 digits)")
    validate.add_argument("--external-id", required=True, help="ExternalId for this client")
    validate.set_defaults(handler=_aws_validate)

    args = parser.parse_args(argv)
    # Keep JSON logs quiet in a terminal session; errors still show.
    configure_logging("WARNING")
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
