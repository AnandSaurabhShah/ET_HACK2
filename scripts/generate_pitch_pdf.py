from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "submission" / "Aegis-CNI_ET_GenAI_Hackathon_Pitch.pdf"
PAGE_SIZE = landscape((13.333 * inch, 7.5 * inch))

NAVY = colors.HexColor("#18324A")
GREEN = colors.HexColor("#2F855A")
MUTED = colors.HexColor("#5D6B7A")
LIGHT = colors.HexColor("#EEF2F6")
INK = colors.HexColor("#132638")
ACCENT = colors.HexColor("#B83B46")


def styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=34,
            leading=40,
            textColor=INK,
            alignment=TA_LEFT,
            spaceAfter=14,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=15,
            leading=21,
            textColor=MUTED,
            spaceAfter=16,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=12,
            leading=16,
            textColor=INK,
            spaceAfter=7,
        ),
        "small": ParagraphStyle(
            "small",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=MUTED,
        ),
        "center": ParagraphStyle(
            "center",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=INK,
            alignment=TA_CENTER,
        ),
        "metric": ParagraphStyle(
            "metric",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=GREEN,
            alignment=TA_CENTER,
        ),
    }


S = styles()


def para(text: str, style: str = "body") -> Paragraph:
    return Paragraph(text.replace("&", "&amp;"), S[style])


def bullets(items: list[str]) -> list[Paragraph]:
    return [para(f"- {item}") for item in items]


def header_footer(canvas, doc):
    canvas.saveState()
    width, height = PAGE_SIZE
    canvas.setFillColor(NAVY)
    canvas.rect(0, height - 0.44 * inch, width, 0.44 * inch, fill=1, stroke=0)
    canvas.setFillColor(GREEN)
    canvas.rect(0, height - 0.50 * inch, width, 0.06 * inch, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.setFillColor(colors.white)
    canvas.drawString(0.48 * inch, height - 0.29 * inch, "Aegis-CNI | ET GenAI Hackathon 2.0")
    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(width - 0.48 * inch, height - 0.29 * inch, f"Slide {doc.page}")
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(0.48 * inch, 0.26 * inch, "Working production-shaped prototype. Live attack demo + GenAI SOC Copilot + ATT&CK + digital twin + audit.")
    canvas.restoreState()


def card_table(rows, col_widths, style=None):
    table = Table(rows, colWidths=col_widths, hAlign="LEFT")
    base = [
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#CCD6E0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DDE5EE")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]
    table.setStyle(TableStyle(base + (style or [])))
    return table


def slide(title: str, subtitle: str = "", body=None):
    content = [para(title, "title")]
    if subtitle:
        content.append(para(subtitle, "subtitle"))
    if body:
        content.extend(body)
    content.append(Spacer(1, 0.2 * inch))
    content.append(PageBreak())
    return content


def build_story():
    story = []

    story += slide(
        "Aegis-CNI",
        "AI cyber resilience for critical national examination infrastructure.",
        [
            Spacer(1, 0.12 * inch),
            card_table(
                [[para("Detect", "center"), para("Predict", "center"), para("Attribute", "center"), para("Simulate", "center"), para("Mitigate", "center"), para("Audit", "center")]],
                [1.75 * inch] * 6,
                [("BACKGROUND", (0, 0), (-1, -1), LIGHT), ("TEXTCOLOR", (0, 0), (-1, -1), INK)],
            ),
            Spacer(1, 0.32 * inch),
            para("Protected asset: CBSE-style digital examination portal with candidate, invigilator, examiner, certificate, and SOC workflows."),
            para("Submission claim: live attacks are converted into scored telemetry, ATT&CK attribution, source blocking, digital-twin simulation, and hash-chained audit evidence."),
        ],
    )

    story += slide(
        "Why This Matters",
        "Exam infrastructure is a public-trust system. Breach or downtime can disrupt students, institutions, results, and national confidence.",
        bullets(
            [
                "Signature-only security reacts after known compromise patterns exist.",
                "Low-and-slow APT behaviour requires behavioural intelligence and sequence analysis.",
                "Zero-day posture must rely on anomaly, prediction, containment, and auditability.",
                "Judges can verify the system live using terminal attack commands, not just seeded screenshots.",
            ]
        ),
    )

    story += slide(
        "What We Built",
        "A full cyber-resilience loop around a running portal and FastAPI backend.",
        [
            card_table(
                [
                    [para("<b>Frontend</b><br/>CBSE-style portal, MFA login, SOC dashboard, digital twin, Copilot"), para("<b>Backend</b><br/>FastAPI middleware, ML scoring, ATT&CK RAG, SOAR, audit")],
                    [para("<b>GenAI</b><br/>Online Ollama, local Ollama fallback, offline deterministic fallback"), para("<b>Controls</b><br/>IP block, redirect guard, spoofing guard, password policy, AI guard")],
                ],
                [5.7 * inch, 5.7 * inch],
            )
        ],
    )

    story += slide(
        "AI/ML Pipeline",
        "The alert decision is based on behaviour, not only database lookup.",
        bullets(
            [
                "IsolationForest anomaly scoring over telemetry features.",
                "Z-score baseline deviation for latency, bytes, role, segment, and event pattern.",
                "Predictive risk model using rare transitions and short-window entity pressure.",
                "MITRE ATT&CK retrieval over a local Enterprise ATT&CK corpus.",
                "GenAI attribution produces defensive evidence, likely next stage, and mitigation guidance.",
            ]
        ),
    )

    story += slide(
        "Live Mitigation Coverage",
        "Aegis-CNI actively blocks selected live web, identity, redirect, spoofing, and AI-prompt attack classes.",
        [
            card_table(
                [
                    [para("SQLi / command injection"), para("XSS / path traversal"), para("Brute force / scan burst")],
                    [para("Open redirect"), para("IP spoofing / untrusted XFF"), para("AI prompt injection")],
                ],
                [3.8 * inch, 3.8 * inch, 3.8 * inch],
                [("BACKGROUND", (0, 0), (-1, -1), LIGHT)],
            ),
            Spacer(1, 0.18 * inch),
            para("Detected live attacks become telemetry, alerts, ATT&CK mappings, active source blocks, and audit records. Follow-up requests return HTTP 403."),
        ],
    )

    story += slide(
        "GenAI Safety",
        "The system protects the AI surface as well as the web surface.",
        bullets(
            [
                "SOC Copilot answers only portal-security and incoming-attack questions.",
                "Prompt injection, jailbreak, system-prompt leakage, tool override, and API-key exfiltration prompts are blocked before GenAI execution.",
                "Provider chain: online Ollama -> local Ollama -> offline deterministic fallback.",
                "Output is defensive-only: evidence, likely next stage, containment, verification, and recovery.",
            ]
        ),
    )

    story += slide(
        "Cyber Resilience Digital Twin",
        "Graph-based what-if simulation for attack paths and impact analysis.",
        bullets(
            [
                "Models assets: perimeter/WAF, candidate portal, certificate service, auth DB, marking portal, proctoring, SOC.",
                "Tracks asset criticality, controls, live alert pressure, and blocked source count.",
                "Simulates likely attack path and risk-before/risk-after containment posture.",
                "Model-only by design: no live user session or production network is touched.",
            ]
        ),
    )

    story += slide(
        "Demo Flow",
        "A five-minute judge demo proves the platform is live.",
        bullets(
            [
                "Sign in as SOC operator with MFA.",
                "Run a safe terminal attack, such as SQLi or AI prompt injection.",
                "Watch live alert, score, latency, bytes, attribution, and blocklist update.",
                "Show follow-up request returns HTTP 403.",
                "Ask SOC Copilot: 'Why was this blocked?'",
                "Run digital twin simulation and verify `/audit/verify`.",
            ]
        ),
    )

    story += slide(
        "Measured Impact",
        "Generated by the repository evaluation harness.",
        [
            card_table(
                [
                    [para("Detection Rate", "center"), para("ATT&CK Accuracy", "center"), para("MTTD Improvement", "center"), para("MTTR Improvement", "center")],
                    [para("80.56%", "metric"), para("100.00%", "metric"), para("10080.0x", "metric"), para("68.6x", "metric")],
                    [para("Local ATT&CK techniques", "center"), para("Labelled attacks", "center"), para("Autonomous playbook steps", "center"), para("Chroma ready", "center")],
                    [para("697", "metric"), para("108", "metric"), para("75.0%", "metric"), para("True", "metric")],
                ],
                [2.85 * inch] * 4,
            )
        ],
    )

    story += slide(
        "Production Readiness",
        "Honest path from hackathon prototype to critical-infrastructure deployment.",
        bullets(
            [
                "Already implemented: live middleware, ML scoring, GenAI attribution, source blocking, MFA demo, password policy, digital twin, audit verification.",
                "Enterprise integrations needed: SIEM, EDR, IAM, WAF/firewall, cloud audit, CMDB, notification systems, Redis blocklist, observability.",
                "Submission includes deployment configs, demo scripts, judge Q&A, one-page summary, and a generated 90-second pitch video.",
            ]
        ),
    )

    story += slide(
        "Submission Links",
        "Ready for ET GenAI Hackathon review.",
        [
            para("<b>GitHub:</b> https://github.com/AnandSaurabhShah/ET_HACK2"),
            para("<b>Demo credentials:</b> SOC-AEGIS-001 / security"),
            para("<b>Key docs:</b> README.md, DEPLOYMENT.md, PRODUCTION_READINESS.md, RESULTS.md, submission/"),
            Spacer(1, 0.2 * inch),
            para("Closing line: Aegis-CNI demonstrates the resilience loop ET GenAI asks for: detect, predict, attribute, simulate, mitigate, and prove.", "subtitle"),
        ],
    )

    if story and isinstance(story[-1], PageBreak):
        story.pop()
    return story


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=PAGE_SIZE,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.76 * inch,
        bottomMargin=0.48 * inch,
        title="Aegis-CNI ET GenAI Hackathon Pitch",
        author="Aegis-CNI Team",
    )
    doc.build(build_story(), onFirstPage=header_footer, onLaterPages=header_footer)
    print(OUT)


if __name__ == "__main__":
    main()
