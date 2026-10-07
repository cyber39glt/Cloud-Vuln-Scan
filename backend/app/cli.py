"""Command-line tools for developers and consultants (until the web UI exists).

Clients
    clients add "Acme Ltd"                 register a client
    clients list
AWS
    aws connect --client "Acme Ltd" --account-id 123456789012
        create (or show) the client's connection and its ExternalId
    aws validate --account-id ... (--client "Acme Ltd" | --external-id ...)
    aws scan --account-id ... (--client "Acme Ltd" [--assessment NAME] | --external-id ...)
             [--regions eu-west-2,us-east-1] [--json]
        With --client the results are SAVED; with --external-id they are only printed.
    aws external-id                        generate an ExternalId (unsaved)
Assessments
    assessments list --client "Acme Ltd"
    assessments show --client "Acme Ltd" --scan <scan-id> [--json]
    assessments export --client "Acme Ltd" --scan <scan-id> [--format json|csv|all]
        write report files to the exports/ folder (git-ignored: they contain client data)
"""

import argparse
import json
import os
import re
import sys
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.console import UNVERIFIED_NOTE, format_summary
from app.core.config import get_settings
from app.core.database import get_sessionmaker
from app.core.logging import configure_logging
from app.domain.enums import Provider
from app.domain.findings import AssessmentResult
from app.providers.aws.errors import describe_aws_error
from app.providers.aws.session import AwsConnection, generate_external_id
from app.providers.aws.validation import validate_connection
from app.reporting.exports import to_csv, to_json
from app.reporting.report import report_for_scan
from app.scanning import WrongAccountError, scan_aws
from app.storage import repository as repo

# ASCII markers: Windows consoles do not always display symbols such as check marks.
_MARKERS = {"ok": "[ OK ]", "failed": "[FAIL]", "skipped": "[SKIP]"}


class CliError(Exception):
    """A problem to explain to the user (printed without a traceback)."""


def _db(work: Callable[[Session], int]) -> int:
    """Run `work` in one database transaction (committed only if it succeeds)."""
    try:
        with get_sessionmaker().begin() as session:
            return work(session)
    except OperationalError as exc:
        raise CliError(
            "The database is not reachable. Start it with: .\\scripts\\dev.ps1 up"
        ) from exc
    except repo.NotFoundError as exc:
        raise CliError(str(exc).capitalize() + ".") from exc


def _print_result(result: AssessmentResult, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result.model_dump(mode="json"), indent=2))
    else:
        print(format_summary(result))
        print(f"\n{UNVERIFIED_NOTE}")


# ------------------------------------------------------------------ clients


def _clients_add(args: argparse.Namespace) -> int:
    def work(db: Session) -> int:
        try:
            with db.begin_nested():
                client = repo.create_client(db, args.name)
        except IntegrityError as exc:
            raise CliError(
                "A client with that name already exists (or the name is blank)."
            ) from exc
        print(f"Client created: {client.name}  (id {client.id})")
        return 0

    return _db(work)


def _clients_list(_: argparse.Namespace) -> int:
    def work(db: Session) -> int:
        clients = repo.list_clients(db)
        if not clients:
            print('No clients yet. Add one with: clients add "Client name"')
        for client in clients:
            print(f"{client.id}  {client.name}")
        return 0

    return _db(work)


# ------------------------------------------------------------------ AWS


def _aws_connection(args: argparse.Namespace) -> AwsConnection:
    """Build the connection from --external-id, or from the client's saved connection."""
    role_name = get_settings().aws_assessment_role_name
    external_id = getattr(args, "external_id", None)
    if args.client:

        def work(db: Session) -> int:
            nonlocal external_id
            client = repo.find_client(db, args.client)
            try:
                external_id = repo.get_connection(
                    db, client.id, Provider.AWS, args.account_id
                ).external_id
            except repo.NotFoundError as exc:
                raise CliError(
                    "This client has no connection for that account yet. Run: aws connect "
                    f'--client "{client.name}" --account-id {args.account_id}'
                ) from exc
            return 0

        _db(work)
    if not external_id:
        raise CliError("Provide either --client or --external-id.")
    try:
        return AwsConnection(args.account_id, external_id, role_name)
    except ValueError as exc:
        raise CliError(f"Invalid input: {exc}") from exc


def _aws_external_id(_: argparse.Namespace) -> int:
    print(generate_external_id(get_settings().consultancy_name))
    return 0


def _aws_connect(args: argparse.Namespace) -> int:
    settings = get_settings()
    try:
        AwsConnection(args.account_id, "placeholder", settings.aws_assessment_role_name)
    except ValueError as exc:
        raise CliError(f"Invalid input: {exc}") from exc

    def work(db: Session) -> int:
        client = repo.find_client(db, args.client)
        connection = repo.get_or_create_aws_connection(
            db, client.id, args.account_id, settings.consultancy_name
        )
        print(f"Client     : {client.name}")
        print(f"AWS account: {connection.account_id}")
        print(f"Role name  : {settings.aws_assessment_role_name}")
        print(f"ExternalId : {connection.external_id}")
        print(
            "\nSend the client infra/aws/client-onboarding-role.yaml with the ExternalId above"
            "\nand the platform identity ARN (see docs/aws-connection.md, 'Client onboarding')."
            f'\nThen run: aws validate --client "{client.name}" --account-id {args.account_id}'
        )
        return 0

    return _db(work)


def _aws_validate(args: argparse.Namespace) -> int:
    connection = _aws_connection(args)
    print(f"Validating AWS account {connection.account_id} via {connection.role_arn}\n")
    report = validate_connection(connection, get_settings())
    for check in report.checks:
        detail = f"  {check.detail}" if check.detail else ""
        print(f"{_MARKERS[check.status]} {check.name}{detail}")
    print("\nConnection is ready." if report.ok else "\nConnection is NOT ready.")
    return 0 if report.ok else 1


def _aws_scan(args: argparse.Namespace) -> int:
    connection = _aws_connection(args)
    regions = [r.strip() for r in args.regions.split(",") if r.strip()] if args.regions else None
    if not args.json:
        scope = ", ".join(regions) if regions else "all enabled regions"
        print(f"Assessing AWS account {connection.account_id} ({scope}). Read-only.")

    try:
        result = scan_aws(connection, get_settings(), regions=regions)
    except WrongAccountError as exc:
        raise CliError(f"Stopped before collecting anything: {exc}") from exc
    except Exception as exc:
        problem = describe_aws_error(exc)
        raise CliError(
            f"Scan failed: {problem.message} {problem.hint}".strip()
            + "\nTip: run 'aws validate' with the same values to diagnose."
        ) from exc

    _print_result(result, args.json)
    if args.client:
        _save_scan(args, result)
    elif not args.json:
        print("\n(Not saved: use --client to store results.)")
    return 0


def _save_scan(args: argparse.Namespace, result: AssessmentResult) -> None:
    def work(db: Session) -> int:
        client = repo.find_client(db, args.client)
        connection = repo.get_connection(db, client.id, Provider.AWS, args.account_id)
        name = args.assessment or f"AWS assessment {args.account_id}"
        assessment = repo.get_or_create_assessment(db, client.id, connection.id, name)
        scan = repo.save_scan_result(db, client.id, assessment.id, result)
        if not args.json:
            print(f'\nSaved to assessment "{assessment.name}" as scan {scan.id}.')
        return 0

    _db(work)


# ------------------------------------------------------------------ assessments


def _assessments_list(args: argparse.Namespace) -> int:
    def work(db: Session) -> int:
        client = repo.find_client(db, args.client)
        assessments = repo.list_assessments(db, client.id)
        if not assessments:
            print(f"No assessments for {client.name} yet.")
        for assessment in assessments:
            print(f"\n{assessment.name}  [{assessment.status.value}]  (id {assessment.id})")
            for scan in repo.list_scan_runs(db, client.id, assessment.id):
                findings = len(scan.result.get("findings", []))
                print(
                    f"  scan {scan.id}  {scan.completed_at:%Y-%m-%d %H:%M} UTC  "
                    f"{scan.provider.value} {scan.account_id}  {findings} findings"
                )
        return 0

    return _db(work)


def _scan_id(args: argparse.Namespace) -> uuid.UUID:
    try:
        return uuid.UUID(args.scan)
    except ValueError as exc:
        raise CliError("--scan must be a scan ID (see: assessments list).") from exc


def _assessments_show(args: argparse.Namespace) -> int:
    scan_id = _scan_id(args)

    def work(db: Session) -> int:
        client = repo.find_client(db, args.client)
        try:
            result = repo.load_scan_result(db, client.id, scan_id)
        except repo.IntegrityViolation as exc:
            raise CliError("This stored scan FAILED its integrity check (hash mismatch).") from exc
        _print_result(result, args.json)
        return 0

    return _db(work)


# Relative to the working directory: backend/exports on your computer (git-ignored).
EXPORT_DIR = Path("exports")


def _write_private_file(path: Path, content: bytes) -> None:
    """Create a new file readable only by its owner; never overwrite an existing one."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(content)


def _assessments_export(args: argparse.Namespace) -> int:
    scan_id = _scan_id(args)
    settings = get_settings()

    def work(db: Session) -> int:
        client = repo.find_client(db, args.client)
        try:
            report = report_for_scan(db, client.id, scan_id, settings.consultancy_name)
        except repo.IntegrityViolation as exc:
            raise CliError("This stored scan FAILED its integrity check (hash mismatch).") from exc

        # File names are built only from safe characters: client names are free text.
        slug = re.sub(r"[^A-Za-z0-9]+", "-", client.name).strip("-").lower()[:40] or "client"
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        base = f"{slug}_{str(scan_id)[:8]}_{stamp}"
        renderers = {"json": to_json, "csv": to_csv}
        formats = renderers if args.format == "all" else {args.format: renderers[args.format]}

        EXPORT_DIR.mkdir(exist_ok=True)
        for extension, render in formats.items():
            path = EXPORT_DIR / f"{base}.{extension}"
            _write_private_file(path, render(report))
            print(f"Written: {path.as_posix()}")
        print("These files contain client data: store and share them accordingly.")
        return 0

    return _db(work)


# ------------------------------------------------------------------ parser


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__.splitlines()[0])
    groups = parser.add_subparsers(dest="group", required=True)

    clients = groups.add_parser("clients", help="manage clients").add_subparsers(
        dest="command", required=True
    )
    add = clients.add_parser("add", help="register a client")
    add.add_argument("name")
    add.set_defaults(handler=_clients_add)
    clients.add_parser("list", help="list clients").set_defaults(handler=_clients_list)

    aws = groups.add_parser("aws", help="AWS connection and assessment tools").add_subparsers(
        dest="command", required=True
    )
    aws.add_parser("external-id", help="generate an ExternalId").set_defaults(
        handler=_aws_external_id
    )
    connect = aws.add_parser("connect", help="create/show a client's AWS connection")
    connect.add_argument("--client", required=True, help="client name or ID")
    connect.add_argument("--account-id", required=True, help="AWS account ID (12 digits)")
    connect.set_defaults(handler=_aws_connect)

    for name, handler, help_text in (
        ("validate", _aws_validate, "validate a client connection"),
        ("scan", _aws_scan, "run a read-only assessment"),
    ):
        command = aws.add_parser(name, help=help_text)
        command.add_argument("--account-id", required=True, help="AWS account ID (12 digits)")
        source = command.add_mutually_exclusive_group(required=True)
        source.add_argument("--client", help="client name or ID (uses the saved connection)")
        source.add_argument("--external-id", help="ExternalId, for unsaved one-off use")
        if name == "scan":
            command.add_argument("--assessment", help="assessment name (with --client)")
            command.add_argument("--regions", help="comma-separated regions (default: all)")
            command.add_argument("--json", action="store_true", help="print the full dataset")
        command.set_defaults(handler=handler)

    assessments = groups.add_parser("assessments", help="view saved assessments").add_subparsers(
        dest="command", required=True
    )
    listing = assessments.add_parser("list", help="list a client's assessments and scans")
    listing.add_argument("--client", required=True, help="client name or ID")
    listing.set_defaults(handler=_assessments_list)
    show = assessments.add_parser("show", help="show a saved scan")
    show.add_argument("--client", required=True, help="client name or ID")
    show.add_argument("--scan", required=True, help="scan ID")
    show.add_argument("--json", action="store_true", help="print the full dataset")
    show.set_defaults(handler=_assessments_show)
    export = assessments.add_parser("export", help="write JSON/CSV report files")
    export.add_argument("--client", required=True, help="client name or ID")
    export.add_argument("--scan", required=True, help="scan ID")
    export.add_argument("--format", choices=("json", "csv", "all"), default="all")
    export.set_defaults(handler=_assessments_export)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    # Keep JSON logs quiet in a terminal session; errors still show.
    configure_logging("WARNING")
    try:
        return args.handler(args)
    except CliError as exc:
        print(exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
