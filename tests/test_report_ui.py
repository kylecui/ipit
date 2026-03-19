"""Regression tests for report UI rendering paths."""

from __future__ import annotations

import asyncio
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from app.i18n import i18n
from app.llm_client import llm_client
from models import EvidenceItem, Verdict
from plugins.builtin.threatbook import ThreatBookPlugin
from reporters.html_reporter import HTMLReporter
from reporters.narrative_reporter import NarrativeReporter


def _ownership_section(html: str, lang: str) -> str:
    t = i18n.get_translator(lang)
    title = t("narrative.section_ownership")
    next_title = t("narrative.section_domain")
    start = html.index(title)
    end = html.index(next_title, start)
    return html[start:end]


def _build_verdict() -> Verdict:
    return Verdict(
        object_type="ip",
        object_value="1.2.3.4",
        reputation_score=42,
        contextual_score=3,
        final_score=45,
        level="Medium",
        confidence=0.82,
        decision="review",
        summary="Suspicious activity observed.",
        evidence=[
            EvidenceItem(
                source="virustotal",
                category="reputation",
                severity="medium",
                title="Community detections",
                detail="Several vendors flagged the IP.",
                score_delta=15,
                confidence=0.8,
            )
        ],
        tags=["scanner"],
        raw_sources={
            "virustotal": {
                "ok": True,
                "data": {
                    "malicious_count": 2,
                    "suspicious_count": 1,
                    "harmless_count": 10,
                    "undetected_count": 20,
                    "related_domains": ["example.test"],
                },
            },
            "reverse_dns": {
                "ok": True,
                "data": {
                    "hostname": "host.example.test",
                    "aliases": ["alias.example.test"],
                },
            },
        },
    )


def test_narrative_report_shows_fallback_banner_when_llm_requested_but_unavailable(
    monkeypatch,
) -> None:
    """Requested LLM reports must show the explicit template fallback banner."""
    reporter = NarrativeReporter()
    verdict = _build_verdict()
    t = i18n.get_translator("en")

    monkeypatch.setattr(llm_client, "is_enabled", lambda overrides=None: True)

    async def _fake_generate(*args, **kwargs):
        return None

    monkeypatch.setattr(llm_client, "generate", _fake_generate)

    html, llm_enhanced, llm_fallback = asyncio.run(
        reporter.generate(
            verdict,
            lang="en",
            llm_overrides={
                "source": "personal",
                "api_key": "secret",
                "model": "test-model",
                "base_url": "https://api.example.test/v1",
            },
        )
    )

    assert llm_enhanced is False
    assert llm_fallback is True
    assert t("narrative.llm_fallback_title") in html
    assert t("narrative.llm_fallback_message") in html
    assert "badge-template" in html


def test_reports_compare_template_renders_llm_and_template_labels() -> None:
    """Compare page should expose report mode labels in selectors and headers."""
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    template = Environment(loader=FileSystemLoader(template_dir)).get_template(
        "reports_compare.html.j2"
    )

    rendered = template.render(
        request=None,
        t=i18n.get_translator("en"),
        lang="en",
        root_path="/v2",
        user={"id": 1, "display_name": "Alice"},
        reports=[
            {
                "id": 11,
                "ip": "1.2.3.4",
                "generated_at": "2026-03-17 12:00:00",
                "lang": "en",
                "llm_enhanced": 1,
            },
            {
                "id": 12,
                "ip": "1.2.3.4",
                "generated_at": "2026-03-17 12:05:00",
                "lang": "en",
                "llm_enhanced": 0,
            },
        ],
        report_history=[
            {
                "id": 11,
                "generated_at": "2026-03-17 12:00:00",
                "lang": "en",
                "llm_enhanced": 1,
            },
            {
                "id": 12,
                "generated_at": "2026-03-17 12:05:00",
                "lang": "en",
                "llm_enhanced": 0,
            },
        ],
        report_a=11,
        report_b=12,
    )

    assert "#11 — 2026-03-17 12:00:00 — en — LLM" in rendered
    assert "#12 — 2026-03-17 12:05:00 — en — Template" in rendered
    assert "#11 · 2026-03-17 12:00:00 · en · LLM" in rendered
    assert "#12 · 2026-03-17 12:05:00 · en · Template" in rendered


def test_narrative_report_uses_secondary_ownership_sources_when_rdap_missing() -> None:
    """Ownership section should fall back to partial attribution when RDAP is absent."""
    reporter = NarrativeReporter()
    verdict = Verdict(
        object_type="ip",
        object_value="150.107.38.251",
        reputation_score=70,
        contextual_score=0,
        final_score=70,
        level="High",
        confidence=0.9,
        decision="alert_and_review",
        summary="High-risk IP.",
        evidence=[],
        tags=[],
        raw_sources={
            "rdap": {"ok": False, "data": {}, "error": "redirect failed"},
            "reverse_dns": {
                "ok": True,
                "data": {
                    "hostname": None,
                    "aliases": [],
                    "error": "No PTR record found",
                },
            },
            "abuseipdb": {
                "ok": True,
                "data": {
                    "isp": "UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED",
                    "country_code": "US",
                },
            },
            "threatbook": {
                "ok": True,
                "data": {
                    "carrier": "优刻得信息科技（香港）有限公司",
                    "country": "香港",
                },
            },
        },
    )

    html, llm_enhanced, llm_fallback = asyncio.run(
        reporter.generate(verdict, lang="zh")
    )
    ownership_html = _ownership_section(html, "zh")

    assert llm_enhanced is False
    assert llm_fallback is False
    assert "UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED" in ownership_html
    assert "香港" in ownership_html
    assert i18n.get_translator("zh")("narrative.no_data") not in ownership_html


def test_narrative_report_shows_no_data_when_ownership_section_is_empty() -> None:
    """Ownership section should render an explicit no-data row instead of a blank table."""
    reporter = NarrativeReporter()
    verdict = Verdict(
        object_type="ip",
        object_value="203.0.113.10",
        reputation_score=10,
        contextual_score=0,
        final_score=10,
        level="Low",
        confidence=0.5,
        decision="allow_with_monitoring",
        summary="Low-risk IP.",
        evidence=[],
        tags=[],
        raw_sources={
            "rdap": {"ok": False, "data": {}, "error": "not available"},
            "reverse_dns": {
                "ok": True,
                "data": {
                    "hostname": None,
                    "aliases": [],
                    "error": "No PTR record found",
                },
            },
        },
    )

    html, _, _ = asyncio.run(reporter.generate(verdict, lang="zh"))
    ownership_html = _ownership_section(html, "zh")

    assert "基础归属分析" in ownership_html
    assert i18n.get_translator("zh")("narrative.no_data") in ownership_html


def test_dashboard_template_renders_current_report_before_history_tables() -> None:
    """Fresh analyze results should appear before recent history on the dashboard."""
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    template = Environment(loader=FileSystemLoader(template_dir)).get_template(
        "dashboard.html.j2"
    )
    t = i18n.get_translator("en")

    rendered = template.render(
        request=None,
        t=t,
        lang="en",
        root_path="/v2",
        user={"id": 1, "display_name": "Alice"},
        ip="1.2.3.4",
        html_report="<section id='fresh-report'>Fresh report</section>",
        recent_queries=[
            {
                "ip": "1.2.3.4",
                "level": "Medium",
                "final_score": 45,
                "queried_at": "2026-03-19 10:00:00",
            }
        ],
        recent_reports=[],
    )

    assert rendered.index("fresh-report") < rendered.index(
        t("dashboard.recent_queries")
    )


def test_html_reporter_renders_all_available_source_status_rows() -> None:
    """HTML report should expose every raw source instead of a hardcoded subset."""
    verdict = _build_verdict().model_copy(
        update={
            "raw_sources": {
                "rdap": {"ok": False, "error": "lookup failed", "data": {}},
                "reverse_dns": {"ok": True, "data": {"hostname": "host.example.test"}},
                "virustotal": {"ok": True, "data": {}},
                "abuseipdb": {"ok": True, "data": {}},
                "shodan": {"ok": False, "error": "rate limited", "data": {}},
                "threatbook": {"ok": True, "data": {"carrier": "Example Carrier"}},
                "greynoise": {
                    "ok": False,
                    "error": "community unavailable",
                    "data": {},
                },
                "internal_flow": {"ok": False, "data": {"error": "No data file found"}},
            }
        }
    )

    html = HTMLReporter().generate(verdict, lang="en")

    assert "ThreatBook" in html
    assert "GreyNoise" in html
    assert "Internal Flow" in html
    assert "community unavailable" in html
    assert "No data file found" in html


def test_threatbook_normalizes_chinese_severity_before_scoring() -> None:
    """ThreatBook Chinese severities should still produce evidence."""
    plugin = ThreatBookPlugin()

    normalized = plugin._normalize(
        {
            "severity": "中",
            "judgments": ["傀儡机", "垃圾邮件", "扫描"],
            "tags_classes": [],
            "basic": {"carrier": "Modat B.V.", "location": {"country": "新加坡"}},
        },
        "212.73.148.12",
    )
    evidence = plugin._score(normalized)

    assert normalized["severity"] == "medium"
    assert len(evidence) == 1
    assert evidence[0].severity == "medium"
    assert evidence[0].score_delta == 15


def test_profile_template_renders_api_usage_summary_card() -> None:
    """Profile page should expose API usage summary metrics."""
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    template = Environment(loader=FileSystemLoader(template_dir)).get_template(
        "admin/profile.html.j2"
    )
    t = i18n.get_translator("en")

    rendered = template.render(
        request=None,
        t=t,
        lang="en",
        root_path="/v2",
        user={"id": 1, "display_name": "Alice", "username": "alice", "is_admin": False},
        msg="",
        usage_snapshot={
            "plugin_overview": {"calls": 12, "success_rate": 0.75},
            "llm_overview": {"calls": 3, "total_tokens": 4567},
        },
    )

    assert t("admin.api_usage") in rendered
    assert t("admin.plugin_api_calls_30d") in rendered
    assert t("admin.llm_calls_30d") in rendered
    assert "4567" in rendered


def test_admin_usage_template_renders_plugin_and_llm_tables() -> None:
    """Admin usage page should render aggregated plugin and LLM usage tables."""
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    template = Environment(loader=FileSystemLoader(template_dir)).get_template(
        "admin/usage.html.j2"
    )
    t = i18n.get_translator("en")

    rendered = template.render(
        request=None,
        t=t,
        lang="en",
        root_path="/v2",
        user={"id": 1, "display_name": "Admin", "username": "admin", "is_admin": True},
        usage_snapshot={
            "plugin_overview": {
                "calls": 11,
                "success_rate": 0.81,
                "avg_latency_ms": 123,
            },
            "plugin_summary": [
                {
                    "plugin_name": "threatbook",
                    "calls": 3,
                    "success_rate": 0.66,
                    "avg_latency_ms": 150,
                    "shared_calls": 3,
                    "personal_calls": 0,
                }
            ],
            "llm_overview": {"calls": 1, "success_rate": 1.0, "total_tokens": 3156},
            "llm_summary": [
                {
                    "source": "personal",
                    "model": "Pro/moonshotai/Kimi-K2.5",
                    "calls": 1,
                    "total_tokens": 3156,
                    "success_rate": 1.0,
                    "avg_latency_ms": 1020,
                }
            ],
        },
    )

    assert t("admin.api_usage") in rendered
    assert "threatbook" in rendered
    assert "Pro/moonshotai/Kimi-K2.5" in rendered
    assert "3156" in rendered
