# Aegis-CNI Submission Kit

This folder contains judge-facing material for ET GenAI Hackathon 2.0.

## Start Here

1. `ONE_PAGE_SUMMARY.md` - concise executive summary.
2. `Aegis-CNI_ET_GenAI_Hackathon_Pitch.pdf` - upload-ready hackathon pitch deck.
3. `JUDGE_WALKTHROUGH.md` - exact live demo flow and commands.
4. `VIDEO_5_MINUTE_DEMO_SCRIPT.md` - narration and timing for the main demo video.
5. `VIDEO_90_SECOND_SCRIPT.md` - short pitch-video narration.
6. `TECHNICAL_BRIEF.md` - architecture and implementation details.
7. `JUDGE_QA.md` - direct answers to likely judge questions.
8. `SHOT_LIST.md` - screen-recording checklist.

## Generated Pitch PDF

`Aegis-CNI_ET_GenAI_Hackathon_Pitch.pdf` is an 11-slide judge-facing pitch deck generated from the project claims and demo flow:

```powershell
python scripts/generate_pitch_pdf.py
```

## Generated Video

`video/aegis_cni_90s_pitch.mp4` is a silent overview video generated from the project script:

```powershell
python scripts/generate_pitch_video.py
```

Use this as an intro video or combine it with a screen recording of the live demo.

## Recommended Final Submission Bundle

- GitHub repository URL.
- Deployed frontend URL.
- Deployed backend `/health` and `/ready` URLs.
- `submission/ONE_PAGE_SUMMARY.md`.
- `submission/Aegis-CNI_ET_GenAI_Hackathon_Pitch.pdf`.
- `submission/JUDGE_WALKTHROUGH.md`.
- 5-minute screen-recorded live demo.
- 90-second pitch video.
- `PRODUCTION_READINESS.md`.
- `RESULTS.md`.
