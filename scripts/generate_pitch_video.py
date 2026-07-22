from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "submission" / "video"
ASSET_DIR = ROOT / "submission" / "assets" / "pitch_frames"
VIDEO_PATH = OUT_DIR / "aegis_cni_90s_pitch.mp4"
FPS = 30
SIZE = (1920, 1080)


SLIDES = [
    (
        "Aegis-CNI",
        "AI cyber resilience for critical national examination infrastructure",
        ["Detect", "Predict", "Attribute", "Simulate", "Mitigate", "Audit"],
        5,
    ),
    (
        "The Risk",
        "Exam portals are national trust infrastructure. Breaches can leak student records, disrupt exams, and compromise evaluation workflows.",
        ["Traditional signatures react late", "APTs operate low-and-slow", "Zero-days require behaviour-first defense"],
        8,
    ),
    (
        "Protected Portal",
        "A CBSE-style sample site with candidate, invigilator, examiner, certificate, and SOC workflows.",
        ["Role-scoped access", "Password policy", "Two-factor authentication", "Live telemetry"],
        8,
    ),
    (
        "Live AI Detection",
        "Every inbound request can become telemetry for anomaly and predictive-risk scoring.",
        ["IsolationForest", "z-score baselines", "rare sequence modelling", "entity pressure"],
        9,
    ),
    (
        "MITRE + GenAI",
        "Alerts are mapped to ATT&CK and explained by a defensive-only SOC Copilot.",
        ["Online Ollama first", "Local Ollama fallback", "Offline deterministic fallback"],
        8,
    ),
    (
        "Active Mitigation",
        "High-confidence live attacks block the source IP and prove enforcement with HTTP 403.",
        ["SQLi", "Command injection", "XSS", "Path traversal", "Open redirect", "AI prompt injection"],
        9,
    ),
    (
        "AI-Attack Guard",
        "Prompt injection, jailbreaks, system-prompt leakage, tool override, and API-key exfiltration prompts are blocked before model execution.",
        ["HTTP perimeter guard", "SOC Copilot guard", "provider: ai-guard"],
        9,
    ),
    (
        "Cyber Resilience Digital Twin",
        "A model-only graph simulates attack paths, asset criticality, live pressure, controls, and post-containment risk.",
        ["Attack path modelling", "Risk before/after", "Control mapping"],
        9,
    ),
    (
        "Auditability",
        "Every score, alert, block, playbook action, and Copilot decision is written to a hash-chained audit log.",
        ["Verify with /audit/verify", "Human approval gates", "Forensic evidence"],
        8,
    ),
    (
        "Impact",
        "Working prototype results from generated evaluation.",
        ["80.56% detection rate", "100.00% ATT&CK attribution accuracy", "10080x MTTD improvement", "697 ATT&CK techniques loaded"],
        8,
    ),
]


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        Path("C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf"),
        Path("C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


def draw_wrapped(draw: ImageDraw.ImageDraw, text: str, xy: tuple[int, int], width: int, fill: str, font_obj, spacing: int = 12) -> int:
    lines: list[str] = []
    for paragraph in text.splitlines():
        words = paragraph.split()
        current = ""
        for word in words:
            candidate = f"{current} {word}".strip()
            if draw.textlength(candidate, font=font_obj) <= width:
                current = candidate
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
    x, y = xy
    line_height = font_obj.size + spacing if hasattr(font_obj, "size") else 40
    for line in lines:
        draw.text((x, y), line, fill=fill, font=font_obj)
        y += line_height
    return y


def make_slide(index: int, title: str, subtitle: str, bullets: list[str]) -> Path:
    image = Image.new("RGB", SIZE, "#eef2f6")
    draw = ImageDraw.Draw(image)

    draw.rectangle((0, 0, 1920, 1080), fill="#eef2f6")
    draw.rectangle((0, 0, 1920, 92), fill="#18324a")
    draw.rectangle((0, 92, 1920, 100), fill="#2f855a")
    draw.text((80, 28), "ET GenAI Hackathon 2.0 | Aegis-CNI", fill="#ffffff", font=font(28, bold=True))
    draw.text((1580, 30), f"{index + 1:02d}/{len(SLIDES):02d}", fill="#cbd5e1", font=font(24))

    draw.text((96, 170), title, fill="#132638", font=font(74, bold=True))
    y = draw_wrapped(draw, subtitle, (100, 285), 1420, "#32465a", font(38), spacing=14)

    y += 42
    for bullet in bullets:
        draw.rounded_rectangle((112, y + 4, 144, y + 36), radius=6, fill="#2f855a")
        draw.text((124, y + 1), "-", fill="#ffffff", font=font(26, bold=True))
        y = draw_wrapped(draw, bullet, (168, y), 1280, "#132638", font(34), spacing=10) + 18

    draw.rounded_rectangle((1380, 710, 1780, 930), radius=16, outline="#18324a", width=4)
    draw.text((1430, 750), "LIVE LOOP", fill="#18324a", font=font(34, bold=True))
    for i, label in enumerate(["Detect", "Predict", "Mitigate"]):
        draw.text((1435, 810 + i * 42), label, fill="#2f855a", font=font(28, bold=True))

    out = ASSET_DIR / f"slide_{index:02d}.png"
    image.save(out)
    return out


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    frames = []
    concat_file = OUT_DIR / "pitch_concat.txt"
    with concat_file.open("w", encoding="utf-8") as handle:
        for index, (title, subtitle, bullets, duration) in enumerate(SLIDES):
            frame = make_slide(index, title, subtitle, bullets)
            frames.append(frame)
            handle.write(f"file '{frame.as_posix()}'\n")
            handle.write(f"duration {duration}\n")
        handle.write(f"file '{frames[-1].as_posix()}'\n")

    cmd = [
        "ffmpeg",
        "-y",
        "-f",
        "concat",
        "-safe",
        "0",
        "-i",
        str(concat_file),
        "-vf",
        f"fps={FPS},format=yuv420p",
        "-movflags",
        "+faststart",
        str(VIDEO_PATH),
    ]
    subprocess.run(cmd, check=True)
    print(VIDEO_PATH)


if __name__ == "__main__":
    main()
