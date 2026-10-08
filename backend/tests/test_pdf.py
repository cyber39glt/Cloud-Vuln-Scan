"""PDF reports: content, escaping of client-controlled text, and the renderer's
refusal to fetch anything (no network, no local files)."""

import io
import urllib.request
import uuid

import pytest
from pypdf import PdfReader

from app.domain.enums import Provider
from app.reporting import pdf
from app.reporting.report import ReportSource, build_report
from app.rules.engine import RuleEngine
from app.sample_data import sample_aws_inventory
from tests.factories import ingress, inventory, security_group

HOSTILE = '<img src="http://169.254.169.254/latest/meta-data/"><b>x</b>{{ 7*7 }}'


def _report(client_name="Demo Client", status="in_review", result=None, report_status="draft"):
    return build_report(
        result or RuleEngine().run(sample_aws_inventory()),
        ReportSource(
            consultancy="SubtleTech",
            client_name=client_name,
            assessment_id=uuid.uuid4(),
            assessment_name="Q1 review",
            assessment_status=status,
            scan_id=uuid.uuid4(),
            scan_sha256="a" * 64,
            report_status=report_status,
        ),
    )


def _text(data: bytes) -> str:
    """All text in the PDF, with line breaks and repeated spaces collapsed."""
    pages = PdfReader(io.BytesIO(data)).pages
    return " ".join(" ".join(page.extract_text() for page in pages).split())


@pytest.fixture(scope="module")
def sample_pdf() -> bytes:
    return pdf.to_pdf(_report())


def test_pdf_has_the_report_content(sample_pdf):
    assert sample_pdf.startswith(b"%PDF-")
    reader = PdfReader(io.BytesIO(sample_pdf))
    assert len(reader.pages) >= 8
    assert reader.metadata.title == "Cloud Security Assessment — Demo Client"
    assert reader.metadata.author == "SubtleTech"
    text = _text(sample_pdf)
    for expected in (
        "Cloud Security Assessment Report",
        "Executive summary",
        "RDS database is publicly accessible",
        "Detailed findings",
        "Framework mapping",
        "DRAFT",
        "a" * 64,  # scan fingerprint
        "could not be evaluated",
    ):
        assert expected in text, expected


def test_final_report_is_not_marked_draft():
    assert "DRAFT" not in _text(pdf.to_pdf(_report(status="finalized", report_status="final")))


def test_report_without_findings():
    from app.rules.common.net_001_ssh_open_to_internet import SshOpenToInternet

    clean = RuleEngine(rules=(SshOpenToInternet(),)).run(
        inventory(Provider.AWS, security_group("ok"))
    )
    text = _text(pdf.to_pdf(_report(result=clean)))
    assert "No findings were identified." in text


def test_client_text_is_escaped_never_markup():
    hostile = RuleEngine().run(inventory(Provider.AWS, security_group(HOSTILE, ingress(port=22))))
    html = pdf.render_html(_report(client_name=HOSTILE, result=hostile))
    assert "<img src=" not in html and "<b>x</b>" not in html
    assert "&lt;img src=&#34;http://169.254.169.254" in html
    assert "{{ 7*7 }}" in html and "49" not in html.split("{{ 7*7 }}")[0][-5:]


def test_findings_are_numbered_and_sorted_by_severity():
    groups = pdf.build_context(_report())["groups"]
    assert [g.number for g in groups[:2]] == ["F-01", "F-02"]
    ranks = [g.severity.rank for g in groups]
    assert ranks == sorted(ranks, reverse=True)


def test_framework_appendix_is_ordered_naturally():
    frameworks = pdf.build_context(_report())["frameworks"]
    assert [f["name"].split()[0] for f in frameworks] == ["CIS", "NIST", "AICPA"]
    cis = [c["id"] for c in frameworks[0]["controls"]]
    assert cis.index("1.8") < cis.index("1.10")


# ------------------------------------------------------------------ no fetching, ever


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "https://example.com/logo.png",
        "file:///etc/passwd",
        "ftp://example.com/x",
    ],
)
def test_fetcher_refuses_anything_but_data_uris(url):
    with pytest.raises(ValueError, match="not allowed"):
        pdf._no_fetch_fetcher().fetch(url)


def test_fetcher_allows_inline_data():
    response = pdf._no_fetch_fetcher().fetch("data:text/plain,hello")
    assert response is not None


def test_renderer_never_opens_external_urls(monkeypatch, caplog):
    """Even if markup with external references reached the renderer, nothing is
    fetched: the HTML is rendered, the references are skipped."""
    opened = []
    real_open = urllib.request.OpenerDirector.open

    def spy(self, request, *args, **kwargs):
        url = request if isinstance(request, str) else request.full_url
        opened.append(url)
        return real_open(self, request, *args, **kwargs)

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", spy)
    monkeypatch.setattr(
        pdf,
        "render_html",
        lambda _report: (
            '<html><head><link rel="stylesheet" href="file:///etc/passwd"></head>'
            '<body><img src="http://127.0.0.1:9/x.png"><p>body</p></body></html>'
        ),
    )
    with caplog.at_level("WARNING", logger="app.reporting.pdf"):
        data = pdf.to_pdf(_report())
    assert data.startswith(b"%PDF-")
    assert not [u for u in opened if not u.startswith("data:")]
    assert any("blocked a resource fetch" in r.getMessage() for r in caplog.records)
