# Aegis-CNI Ollama Model

This folder packages a local Aegis-CNI SOC analyst model for Ollama.

## Create The Model

```powershell
.\scripts\create_ollama_model.ps1
```

The script creates:

```text
aegis-cni:latest
```

from `ollama/Modelfile`.

## What This Is

- A local Ollama model specialised through a defensive system prompt and curated SOC examples.
- Used by backend GenAI attribution and SOC Copilot through Ollama's local `/api/generate` endpoint.
- Safe-by-default: if Ollama is unavailable or returns invalid JSON, the backend falls back to deterministic defensive output.

## What True Weight Fine-Tuning Would Add

Ollama model creation is not the same as training new weights. For true fine-tuning:

1. Train a LoRA/adapter using `ollama/training/aegis_soc_examples.jsonl` plus a larger labelled SOC corpus.
2. Export the adapter in a format compatible with the selected base model.
3. Add an `ADAPTER` line to `ollama/Modelfile`.
4. Re-run `.\scripts\create_ollama_model.ps1`.

The current structure is ready for that upgrade without changing the FastAPI integration.
