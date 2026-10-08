"""Finding review, finalization and reopening (M12): behaviour, locking, history,
outputs, isolation and immutability."""

import csv
import io
import uuid

import pytest
from pypdf import PdfReader
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.domain.enums import Severity
from app.rules.engine import RuleEngine
from app.sample_data import sample_aws_inventory
from app.storage import jobs
from app.storage import repository as repo
from app.storage.models import (
    AuditEvent,
    FindingReview,
    FindingReviewEvent,
    ReviewStatus,
)
from tests.auth_helpers import login, make_user

pytestmark = pytest.mark.integration


@pytest.fixture
def setup(api, db):
    """An assessment with one stored scan of the sample data (10 findings)."""
    client = repo.create_client(db, "Acme Ltd")
    connection = repo.get_or_create_aws_connection(db, client.id, "111122223333", "SubtleTech")
    assessment = repo.create_assessment(db, client.id, connection.id, "Q1")
    result = RuleEngine().run(sample_aws_inventory())
    scan = repo.save_scan_result(db, client.id, assessment.id, result)
    base = f"/api/v1/clients/{client.id}/assessments/{assessment.id}"
    by_rule = {f.rule_id: f.finding_id for f in result.findings}
    return {"client": client, "assessment": assessment, "scan": scan, "base": base, "fp": by_rule}


def _review(api, setup, rule_id, status, severity=None, justification=None):
    body = {"status": status, "severity_override": severity, "justification": justification}
    return api.put(f"{setup['base']}/reviews/{setup['fp'][rule_id]}", json=body)


def _report(api, setup):
    return api.get(f"/api/v1/clients/{setup['client'].id}/scans/{setup['scan'].id}/report").json()


def _events(db, action):
    return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


# ------------------------------------------------------------------ decisions


def test_decisions_shape_the_report(api, setup):
    assert _review(api, setup, "NET-001", "confirmed").status_code == 200
    reason = "Bastion host, restricted by upstream firewall"
    assert _review(api, setup, "NET-002", "false_positive", justification=reason).status_code == 200
    _review(
        api,
        setup,
        "AWS-IAM-005",
        "accepted_risk",
        justification="Client policy: SSO only, no IAM users",
    )
    _review(api, setup, "AWS-EXP-001", "confirmed", "critical", "Holds customer payment data")

    report = _report(api, setup)
    rules = [f["rule_id"] for f in report["findings"]]
    assert "NET-002" not in rules and "AWS-IAM-005" not in rules
    assert [f["rule_id"] for f in report["false_positives"]] == ["NET-002"]
    assert [f["rule_id"] for f in report["accepted_risks"]] == ["AWS-IAM-005"]
    assert report["false_positives"][0]["review"]["justification"] == reason

    rds = report["findings"][0]  # now the most severe
    assert rds["rule_id"] == "AWS-EXP-001" and rds["severity"] == "critical"
    assert rds["review"]["original_severity"] == "high" and rds["review"]["severity_overridden"]
    assert report["summary"]["total_findings"] == 8
    assert report["summary"]["by_severity"]["critical"] == 1
    assert report["summary"]["by_review_status"] == {
        "open": 6,
        "confirmed": 2,
        "false_positive": 1,
        "accepted_risk": 1,
    }
    assert report["source"]["report_status"] == "draft"


@pytest.mark.parametrize(
    "status, severity, justification",
    [
        ("false_positive", None, None),
        ("accepted_risk", None, "too short"),
        ("confirmed", "low", ""),  # a severity change also needs a reason
    ],
)
def test_decisions_that_need_a_reason(api, setup, status, severity, justification):
    response = _review(api, setup, "NET-001", status, severity, justification)
    assert response.status_code == 422
    assert "at least 10 characters" in response.json()["detail"]


def test_database_also_requires_a_reason(db, setup):
    with pytest.raises(IntegrityError), db.begin_nested():
        db.add(
            FindingReview(
                client_id=setup["client"].id,
                assessment_id=setup["assessment"].id,
                fingerprint=setup["fp"]["NET-001"],
                status=ReviewStatus.FALSE_POSITIVE,
                updated_by="test",
            )
        )
        db.flush()


def test_history_and_audit(api, db, setup):
    _review(api, setup, "NET-001", "confirmed")
    _review(api, setup, "NET-001", "accepted_risk", justification="Temporary; ticket SEC-123")
    history = api.get(f"{setup['base']}/reviews/{setup['fp']['NET-001']}/history").json()
    assert [(h["status"], h["previous_status"]) for h in history] == [
        ("accepted_risk", "confirmed"),
        ("confirmed", None),
    ]
    assert history[0]["actor"] == "admin@subtletech.test"
    assert [e.details["status"] for e in _events(db, "finding.reviewed")] == [
        "confirmed",
        "accepted_risk",
    ]
    with pytest.raises(DBAPIError, match="immutable"), db.begin_nested():
        db.execute(text("UPDATE finding_review_events SET status = 'open'"))


def test_unknown_or_foreign_findings_are_not_found(api, db, setup):
    unknown = api.put(f"{setup['base']}/reviews/{'0' * 24}", json={"status": "confirmed"})
    assert unknown.status_code == 404
    other = repo.create_client(db, "Globex")
    foreign = f"/api/v1/clients/{other.id}/assessments/{setup['assessment'].id}"
    response = api.put(f"{foreign}/reviews/{setup['fp']['NET-001']}", json={"status": "confirmed"})
    assert response.status_code == 404


def test_unassigned_consultant_cannot_review(http, db, setup):
    user, secret = make_user(db, "c@subtletech.test", "consultant")
    login(http, db, user, secret)
    response = http.put(
        f"{setup['base']}/reviews/{setup['fp']['NET-001']}", json={"status": "confirmed"}
    )
    assert response.status_code == 404


# ------------------------------------------------------------------ finalization


def _finalize(api, setup, **body):
    return api.post(f"{setup['base']}/finalize", json=body)


def test_finalizing_requires_every_finding_reviewed(api, setup):
    _review(api, setup, "NET-001", "confirmed")
    response = _finalize(api, setup)
    assert response.status_code == 409 and "9 finding(s)" in response.json()["detail"]

    confirm = api.post(
        f"{setup['base']}/reviews/confirm-remaining", json={"scan_id": str(setup["scan"].id)}
    )
    assert confirm.json() == {"confirmed": 9}
    assert _finalize(api, setup).status_code == 200


def test_finalized_assessment_is_locked_and_reports_are_final(api, db, setup):
    _review(api, setup, "NET-002", "false_positive", justification="Bastion host behind VPN only")
    api.post(f"{setup['base']}/reviews/confirm-remaining", json={"scan_id": str(setup["scan"].id)})
    final = _finalize(api, setup).json()

    detail = api.get(setup["base"]).json()
    assert detail["status"] == "finalized"
    assert detail["finalization"]["report_sha256"] == final["report_sha256"]

    report = _report(api, setup)
    assert report["source"]["report_status"] == "final"
    assert report["source"]["finalized_by"] == "admin@subtletech.test"
    assert [f["rule_id"] for f in report["false_positives"]] == ["NET-002"]
    pdf = api.get(f"/api/v1/clients/{setup['client'].id}/scans/{setup['scan'].id}/report.pdf")
    text_ = " ".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.content)).pages)
    assert "DRAFT" not in text_ and "Final" in text_

    # Locked: no review changes, no new scans, no second finalization.
    assert _review(api, setup, "NET-001", "confirmed").status_code == 409
    assert api.post(f"{setup['base']}/scans", json={}).status_code == 409
    assert _finalize(api, setup).status_code == 409
    [event] = _events(db, "assessment.finalized")
    assert event.details["report_sha256"] == final["report_sha256"]


def test_finalized_snapshot_is_tamper_evident(api, db, setup):
    api.post(f"{setup['base']}/reviews/confirm-remaining", json={"scan_id": str(setup["scan"].id)})
    _finalize(api, setup)
    with pytest.raises(DBAPIError, match="immutable"), db.begin_nested():
        db.execute(text("UPDATE assessment_finalizations SET report_sha256 = repeat('0', 64)"))

    # Even someone bypassing the trigger cannot change it unnoticed.
    db.execute(text("ALTER TABLE assessment_finalizations DISABLE TRIGGER USER"))
    db.execute(
        text(
            "UPDATE assessment_finalizations "
            "SET report = jsonb_set(report::jsonb, '{account_id}', '\"999999999999\"')"
        )
    )
    db.execute(text("ALTER TABLE assessment_finalizations ENABLE TRIGGER USER"))
    db.expire_all()
    response = api.get(f"/api/v1/clients/{setup['client'].id}/scans/{setup['scan'].id}/report")
    assert response.status_code == 500
    assert "integrity check" in response.json()["detail"]


def test_cannot_finalize_while_a_scan_runs(api, db, setup):
    api.post(f"{setup['base']}/reviews/confirm-remaining", json={"scan_id": str(setup["scan"].id)})
    jobs.enqueue_scan(db, setup["client"].id, setup["assessment"].id)
    response = _finalize(api, setup)
    assert response.status_code == 409 and "still queued or running" in response.json()["detail"]


# ------------------------------------------------------------------ reopening


def test_reopen_is_admin_only_with_a_reason(api, http, db, setup):
    api.post(f"{setup['base']}/reviews/confirm-remaining", json={"scan_id": str(setup["scan"].id)})
    _finalize(api, setup)

    assert api.post(f"{setup['base']}/reopen", json={"reason": "short"}).status_code == 422
    reason = "Client disputed finding F-03; re-review"
    assert api.post(f"{setup['base']}/reopen", json={"reason": reason}).status_code == 204

    assert api.get(setup["base"]).json()["status"] == "in_review"
    assert len(api.get(f"{setup['base']}/finalizations").json()) == 1  # history kept
    assert _report(api, setup)["source"]["report_status"] == "draft"
    assert _review(api, setup, "NET-001", "accepted_risk", justification=reason).status_code == 200
    [event] = _events(db, "assessment.reopened")
    assert event.details == {"reason": reason}


def test_consultants_cannot_reopen(http, db, setup):
    from app.auth import audit, service

    consultant, secret = make_user(db, "c@subtletech.test", "consultant")
    service.assign_client(db, consultant, setup["client"].id, audit.CLI)
    login(http, db, consultant, secret)
    http.post(f"{setup['base']}/reviews/confirm-remaining", json={"scan_id": str(setup["scan"].id)})
    assert http.post(f"{setup['base']}/finalize", json={}).status_code == 200  # may finalize
    reopen = http.post(f"{setup['base']}/reopen", json={"reason": "I want to change it again"})
    assert reopen.status_code == 403


# ------------------------------------------------------------------ other outputs


def test_csv_and_overview_reflect_reviews(api, setup):
    _review(api, setup, "NET-002", "false_positive", justification="Bastion host behind VPN only")
    _review(api, setup, "NET-001", "confirmed", "medium", "Only reachable from office IP range")
    text = api.get(
        f"/api/v1/clients/{setup['client'].id}/scans/{setup['scan'].id}/report.csv"
    ).content.decode("utf-8-sig")
    header = next(csv.reader(io.StringIO(text)))
    assert {"review_status", "original_severity", "review_justification"} <= set(header)
    assert "false_positive" in text and "Bastion host behind VPN only" in text

    [item] = api.get("/api/v1/overview").json()["items"]
    assert sum(item["latest_scan"]["by_severity"].values()) == 9  # false positive left out
    assert item["latest_scan"]["by_severity"]["high"] == 4  # NET-001 high -> medium
    assert item["latest_scan"]["by_severity"]["medium"] == 5


def test_reviews_carry_over_to_a_rescan(api, db, setup):
    reason = "Bastion host behind VPN only"
    _review(api, setup, "NET-002", "false_positive", justification=reason)
    rescan = repo.save_scan_result(
        db, setup["client"].id, setup["assessment"].id, RuleEngine().run(sample_aws_inventory())
    )
    report = api.get(f"/api/v1/clients/{setup['client'].id}/scans/{rescan.id}/report").json()
    assert [f["rule_id"] for f in report["false_positives"]] == ["NET-002"]
    assert Severity.HIGH.value in {f["severity"] for f in report["findings"]}
    assert uuid.UUID(report["source"]["scan_id"]) == rescan.id
    assert db.scalar(select(FindingReviewEvent.id).limit(1)) is not None
