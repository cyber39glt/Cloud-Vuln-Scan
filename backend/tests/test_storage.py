"""Persistence tests against a real PostgreSQL (integration).

A separate database `<POSTGRES_DB>_test` is created and migrated with Alembic, so
tests never touch development data. Each test runs inside a transaction that is
rolled back afterwards.
"""

import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.rules.engine import RuleEngine
from app.sample_data import sample_aws_inventory
from app.storage import repository as repo
from app.storage.models import AssessmentStatus, FindingRecord, ScanRun


def test_result_hash_is_canonical():
    """Key order and formatting must not change the hash; content changes must."""
    a = {"b": 1, "a": [1, 2], "c": {"y": "é", "x": None}}
    b = {"c": {"x": None, "y": "é"}, "a": [1, 2], "b": 1}
    assert repo.result_hash(a) == repo.result_hash(b)
    assert repo.result_hash(a) != repo.result_hash(a | {"b": 2})
    assert len(repo.result_hash(a)) == 64


def _client_with_scan(db: Session, name: str = "Acme Ltd"):
    client = repo.create_client(db, name)
    connection = repo.get_or_create_aws_connection(db, client.id, "111122223333", "SubtleTech")
    assessment = repo.create_assessment(db, client.id, connection.id, "Q1 AWS review")
    result = RuleEngine().run(sample_aws_inventory())
    scan = repo.save_scan_result(db, client.id, assessment.id, result)
    return client, connection, assessment, scan, result


integration = pytest.mark.integration  # needs the PostgreSQL container


@integration
def test_save_and_load_round_trip(db):
    client, connection, assessment, scan, result = _client_with_scan(db)

    assert connection.external_id.startswith("subtletech-")
    assert assessment.status == AssessmentStatus.IN_REVIEW
    assert scan.regions == list(result.regions)
    stored = db.scalars(select(FindingRecord).where(FindingRecord.scan_run_id == scan.id)).all()
    assert {f.fingerprint for f in stored} == {f.finding_id for f in result.findings}

    loaded = repo.load_scan_result(db, client.id, scan.id)
    assert loaded == result  # identical dataset, field for field


@integration
def test_connection_is_reused_with_the_same_external_id(db):
    client = repo.create_client(db, "Acme Ltd")
    first = repo.get_or_create_aws_connection(db, client.id, "111122223333", "SubtleTech")
    again = repo.get_or_create_aws_connection(db, client.id, "111122223333", "SubtleTech")
    assert first.id == again.id and first.external_id == again.external_id


@integration
def test_another_client_cannot_read_or_write_this_clients_data(db):
    acme, _, assessment, scan, _ = _client_with_scan(db, "Acme Ltd")
    globex = repo.create_client(db, "Globex Corp")

    with pytest.raises(repo.NotFoundError):
        repo.load_scan_result(db, globex.id, scan.id)
    with pytest.raises(repo.NotFoundError):
        repo.save_scan_result(
            db, globex.id, assessment.id, RuleEngine().run(sample_aws_inventory())
        )
    assert repo.list_assessments(db, globex.id) == []
    assert repo.list_scan_runs(db, globex.id, assessment.id) == []
    assert len(repo.list_assessments(db, acme.id)) == 1


@integration
def test_database_rejects_cross_client_links_even_if_code_tries(db):
    """Composite foreign keys: an assessment cannot use another client's connection."""
    acme = repo.create_client(db, "Acme Ltd")
    globex = repo.create_client(db, "Globex Corp")
    acme_connection = repo.get_or_create_aws_connection(db, acme.id, "111122223333", "SubtleTech")

    with pytest.raises(IntegrityError):
        repo.create_assessment(db, globex.id, acme_connection.id, "sneaky")


@integration
def test_stored_findings_and_scans_cannot_be_modified(db):
    _, _, _, scan, _ = _client_with_scan(db)
    finding = db.scalars(select(FindingRecord).where(FindingRecord.scan_run_id == scan.id)).first()

    finding.severity = "low"
    with pytest.raises(DBAPIError, match="immutable"):
        db.flush()


@integration
def test_tampering_with_a_stored_result_is_detected(db):
    """Simulates someone with database access bypassing the trigger."""
    client, _, _, scan, _ = _client_with_scan(db)
    db.execute(text("ALTER TABLE scan_runs DISABLE TRIGGER scan_runs_immutable"))
    db.execute(
        text("UPDATE scan_runs SET result = jsonb_set(result, '{findings}', '[]') WHERE id = :id"),
        {"id": scan.id},
    )
    db.expire_all()

    with pytest.raises(repo.IntegrityViolation):
        repo.load_scan_result(db, client.id, scan.id)


@integration
def test_deleting_a_client_removes_all_its_data(db):
    """DELETE stays possible (data retention / offboarding) and cascades."""
    client, _, _, scan, _ = _client_with_scan(db)
    client_id, scan_id = client.id, scan.id
    db.delete(client)
    db.flush()
    db.expire_all()  # the cascade ran inside PostgreSQL; ask the database, not the cache

    count = "SELECT count(*) FROM {table} WHERE client_id = :client"
    for table in ("cloud_connections", "assessments", "scan_runs", "findings"):
        assert db.execute(text(count.format(table=table)), {"client": client_id}).scalar() == 0
    assert db.execute(select(ScanRun.id).where(ScanRun.id == scan_id)).first() is None


@integration
def test_find_client_by_name_or_id(db):
    client = repo.create_client(db, "  Acme Ltd  ")
    assert client.name == "Acme Ltd"
    assert repo.find_client(db, "Acme Ltd").id == client.id
    assert repo.find_client(db, str(client.id)).id == client.id
    with pytest.raises(repo.NotFoundError):
        repo.find_client(db, "Nobody")
    with pytest.raises(repo.NotFoundError):
        repo.find_client(db, str(uuid.uuid4()))


@integration
@pytest.mark.parametrize("name", ["", "   "])
def test_blank_client_names_are_rejected_by_the_database(db, name):
    with pytest.raises(IntegrityError):
        repo.create_client(db, name)


# ------------------------------------------------------------------ CLI with the database


@pytest.fixture
def cli_db(db, monkeypatch):
    """Point the CLI at the test transaction instead of the development database."""
    from sqlalchemy.orm import sessionmaker

    from app import cli

    factory = sessionmaker(
        bind=db.connection(), join_transaction_mode="create_savepoint", expire_on_commit=False
    )
    monkeypatch.setattr(cli, "get_sessionmaker", lambda: factory)
    return db


@integration
def test_cli_client_connect_scan_save_and_show(cli_db, aws, capsys):
    import boto3

    from app.cli import main

    ec2 = boto3.client("ec2", region_name="us-east-1")
    group = ec2.create_security_group(GroupName="ssh-open", Description="x")["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    account = "123456789012"  # moto's account

    assert main(["clients", "add", "Acme Ltd"]) == 0
    assert main(["clients", "add", "Acme Ltd"]) == 1  # duplicate name
    assert "already exists" in capsys.readouterr().out

    assert main(["aws", "connect", "--client", "Acme Ltd", "--account-id", account]) == 0
    assert "ExternalId : subtletech-" in capsys.readouterr().out

    scan_args = ["aws", "scan", "--client", "Acme Ltd", "--account-id", account]
    assert main([*scan_args, "--regions", "us-east-1", "--assessment", "Q1 review"]) == 0
    out = capsys.readouterr().out
    assert "[HIGH] NET-001 SSH open to the internet" in out
    assert 'Saved to assessment "Q1 review"' in out

    assert main(["assessments", "list", "--client", "Acme Ltd"]) == 0
    listing = capsys.readouterr().out
    assert "Q1 review  [in_review]" in listing
    scan_id = listing.split("scan ")[1].split()[0]

    assert main(["assessments", "show", "--client", "Acme Ltd", "--scan", scan_id]) == 0
    assert "NET-001" in capsys.readouterr().out

    # Another client cannot see it.
    assert main(["clients", "add", "Globex Corp"]) == 0
    assert main(["assessments", "show", "--client", "Globex Corp", "--scan", scan_id]) == 1
    assert "Scan not found." in capsys.readouterr().out


@integration
def test_cli_scan_with_client_requires_a_connection(cli_db, aws, capsys):
    from app.cli import main

    assert main(["clients", "add", "Acme Ltd"]) == 0
    code = main(["aws", "scan", "--client", "Acme Ltd", "--account-id", "123456789012"])
    assert code == 1
    assert "aws connect" in capsys.readouterr().out


# ------------------------------------------------------------------ exports from storage


@integration
def test_cli_exports_a_stored_scan_as_json_and_csv(cli_db, capsys, tmp_path, monkeypatch):
    import csv
    import io
    import stat

    from app.cli import main
    from app.reporting.report import AssessmentReport

    client, _, _, scan, result = _client_with_scan(cli_db, "Acme Ltd / EMEA")
    monkeypatch.chdir(tmp_path)  # exports/ is created under the working directory

    assert main(["assessments", "export", "--client", client.name, "--scan", str(scan.id)]) == 0
    out = capsys.readouterr().out
    assert "contain client data" in out

    files = sorted((tmp_path / "exports").iterdir())
    assert [f.suffix for f in files] == [".csv", ".json", ".pdf"]
    assert files[2].read_bytes().startswith(b"%PDF-")
    assert all(f.name.startswith("acme-ltd-emea_") for f in files)  # safe file names
    assert all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in files)  # owner-only

    report = AssessmentReport.model_validate_json(files[1].read_bytes())
    assert report.source.scan_id == scan.id
    assert report.source.scan_sha256 == scan.result_sha256
    assert [f.finding_id for f in report.findings] == [f.finding_id for f in result.findings]
    rows = list(csv.DictReader(io.StringIO(files[0].read_bytes().decode("utf-8-sig"))))
    assert len(rows) == len(result.findings)


@integration
def test_export_is_client_scoped_and_integrity_checked(cli_db, capsys, tmp_path, monkeypatch):
    from app.cli import main

    _, _, _, scan, _ = _client_with_scan(cli_db, "Acme Ltd")
    repo.create_client(cli_db, "Globex Corp")
    monkeypatch.chdir(tmp_path)

    assert main(["assessments", "export", "--client", "Globex Corp", "--scan", str(scan.id)]) == 1
    assert "Scan not found." in capsys.readouterr().out
    assert not (tmp_path / "exports").exists()  # nothing written

    cli_db.execute(text("ALTER TABLE scan_runs DISABLE TRIGGER scan_runs_immutable"))
    cli_db.execute(
        text("UPDATE scan_runs SET result = jsonb_set(result, '{findings}', '[]') WHERE id = :id"),
        {"id": scan.id},
    )
    assert main(["assessments", "export", "--client", "Acme Ltd", "--scan", str(scan.id)]) == 1
    assert "integrity check" in capsys.readouterr().out


@integration
def test_demo_save_stores_clearly_labelled_sample_data(cli_db, capsys, monkeypatch):
    from sqlalchemy.orm import sessionmaker

    from app import demo

    factory = sessionmaker(bind=cli_db.connection(), join_transaction_mode="create_savepoint")
    monkeypatch.setattr(demo, "get_sessionmaker", lambda: factory)

    demo.main(["--save", "Demo Client"])
    assert "Sample data saved" in capsys.readouterr().out

    client = repo.find_client(cli_db, "Demo Client")
    [assessment] = repo.list_assessments(cli_db, client.id)
    assert assessment.name == demo.DEMO_ASSESSMENT_NAME
    assert len(repo.list_scan_runs(cli_db, client.id, assessment.id)) == 1


# ------------------------------------------------------------------ Azure connections

AZ_TENANT = "22222222-2222-2222-2222-222222222222"
AZ_SUB = "11111111-1111-1111-1111-111111111111"


@integration
def test_azure_connection_stores_tenant_and_no_secret(db):
    client = repo.create_client(db, "Acme Ltd")
    connection = repo.get_or_create_azure_connection(db, client.id, AZ_TENANT.upper(), AZ_SUB)

    assert connection.provider.value == "azure"
    assert (connection.tenant_id, connection.account_id) == (AZ_TENANT, AZ_SUB)  # normalized
    assert connection.external_id is None
    again = repo.get_or_create_azure_connection(db, client.id, AZ_TENANT, AZ_SUB.upper())
    assert again.id == connection.id

    with pytest.raises(ValueError, match="different tenant"):
        repo.get_or_create_azure_connection(
            db, client.id, "99999999-9999-9999-9999-999999999999", AZ_SUB
        )


@integration
def test_database_requires_a_tenant_for_azure_connections(db):
    from app.domain.enums import Provider
    from app.storage.models import CloudConnection

    client = repo.create_client(db, "Acme Ltd")
    db.add(CloudConnection(client_id=client.id, provider=Provider.AZURE, account_id=AZ_SUB))
    with pytest.raises(IntegrityError, match="azure_requires_tenant"):
        db.flush()


@integration
def test_cli_azure_connect_prints_onboarding_steps(cli_db, capsys, monkeypatch):
    from app import cli

    monkeypatch.setattr(
        cli,
        "get_settings",
        lambda: Settings(_env_file=None, azure_client_id="33333333-3333-3333-3333-333333333333"),
    )
    assert cli.main(["clients", "add", "Acme Ltd"]) == 0
    args = ["azure", "connect", "--client", "Acme Ltd", "--tenant-id", AZ_TENANT]
    assert cli.main([*args, "--subscription-id", AZ_SUB]) == 0
    out = capsys.readouterr().out

    assert f"login.microsoftonline.com/{AZ_TENANT}/adminconsent?client_id=3333" in out
    assert f'--role "Reader" --scope /subscriptions/{AZ_SUB}' in out
    assert '--role "Security Reader"' in out

    # validate --client finds the stored tenant; without a platform identity it stops there.
    monkeypatch.setattr(cli, "get_settings", lambda: Settings(_env_file=None))
    code = cli.main(["azure", "validate", "--client", "Acme Ltd", "--subscription-id", AZ_SUB])
    assert code == 1
    assert f"tenant {AZ_TENANT}" in capsys.readouterr().out


@integration
def test_cli_azure_scan_is_saved_and_exportable(cli_db, capsys, tmp_path, monkeypatch):
    from app import cli
    from tests.test_azure_collectors import _scan_with_fakes

    monkeypatch.setattr(cli, "scan_azure", lambda c, s, regions=None: _scan_with_fakes(c, s))
    monkeypatch.chdir(tmp_path)

    assert cli.main(["clients", "add", "Acme Ltd"]) == 0
    connect = ["azure", "connect", "--client", "Acme Ltd", "--tenant-id", AZ_TENANT]
    assert cli.main([*connect, "--subscription-id", AZ_SUB]) == 0
    capsys.readouterr()

    scan = ["azure", "scan", "--client", "Acme Ltd", "--subscription-id", AZ_SUB.upper()]
    assert cli.main(scan) == 0
    out = capsys.readouterr().out
    assert f'Saved to assessment "Azure assessment {AZ_SUB}"' in out
    scan_id = out.split(" as scan ")[1].split(".")[0]

    assert cli.main(["assessments", "list", "--client", "Acme Ltd"]) == 0
    assert f"azure {AZ_SUB}  5 findings" in capsys.readouterr().out
    assert cli.main(["assessments", "export", "--client", "Acme Ltd", "--scan", scan_id]) == 0
    assert len(list((tmp_path / "exports").iterdir())) == 3
