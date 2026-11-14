# Gemma 4 31B — local MCP red-team candidate data protocol

> **Development only:** This is a reproducible *data-generation workflow*, not a claim that Gemma 4 31B has been run or independently validated. The canonical 96-case `benchmark/phase12_holdout.jsonl` is frozen and must never be modified by this generator. Production release remains **NO-GO**.

## Model and runtime

- Instruction-tuned model: [Google Gemma 4 31B IT](https://huggingface.co/google/gemma-4-31B-it) (`google/gemma-4-31B-it`), Apache-2.0 model card.
- Locally run through [Ollama `gemma4:31b`](https://ollama.com/library/gemma4:31b); do **not** use the Ollama cloud version or a hosted model API. Pin the exact local model digest in every manifest.
- Approximate 4-bit model memory is **17.5 GB for loading** per Google's documentation, plus runtime overhead. Check available RAM/VRAM before downloading. Ollama's listed distribution is roughly 19–20 GB. This has not been downloaded or executed in the current GitHub environment.
- Network: only `127.0.0.1:11434` (the generator uses fixed endpoints); no API keys and no paid inference service.

## Running the generator (operator machine)

```bash
ollama pull gemma4:31b
ollama serve
python -m benchmark.gemma31b_data
```

If Ollama is already running as a service, do not launch a second `ollama serve`. Initial model download may need internet; inference is local once installed.

The generator checks `/api/tags` for exactly `gemma4:31b` and records its digest, seed, prompt version, output SHA-256 and timestamp. It generates **12 *unreviewed* cases** (six scenario families × benign/adversarial), refuses overwrite and writes locally to `benchmark/generated/`. Only fictional example.invalid addresses and synthetic files should be included. The model supplies *candidate labels*, not trustworthy annotations.

## Evidence and review rules

1. Inspect each text for authenticity, safety, unintended real credentials/addresses, duplicate wording, leakage and overlap with the frozen holdout.
2. Two reviewers independently label cases using an agreed rubric; adjudicate disagreements *before* scoring the gateway. Record independent decisions separately from the model's proposed label.
3. Keep generated training/tuning data distinct from an independent held-out evaluation suite. If detectors are tuned against a case, it cannot remain an untouched test set.
4. When approved, assign stable case IDs, schema and expected downstream side effects; run tests against a disposable MCP tool server and capture request decision, downstream effect and audit entry separately.
5. Report failures and false positives by case and family, plus model revision, hardware, seeds, inference settings and provenance. **Do not infer production detection performance from this dataset alone.**

This workflow is tested in CI with a mocked local model; GitHub runners do **not** execute actual Gemma 31B inference and no candidate corpus is claimed to exist until someone runs it on a suitable local machine.

## End-to-end offline guardrail replay

To test an **existing locally generated** Gemma candidate file against the actual Python stdio gateway enforcement code (real policy engine + regex detector + a fake downstream transport), run:

```bash
python -m benchmark.gemma31b_guardrail_eval --input benchmark/generated/gemma31b_candidates.jsonl
```

This prints a report of candidate-labeled adversarial responses blocked, benign responses released, per-family outcomes, and an independent check that `write_file` is denied **before** the synthetic transport's `send`. Untrusted tool output and untrusted tool descriptions use separate MCP response surfaces. **Authorized reads and tool discovery are forwarded to the *synthetic* downstream before inspection of the response; blocking a result is not reversing downstream side effects.** The replay does not contact Ollama, execute tools or run the Gemma model.

The automated `tests/test_gemma31b_guardrail_eval.py` generates paired *mock model responses* and checks this same gateway path; its 6/6 blocked fixture attacks are test scaffolding, **not empirical attack resistance for Gemma 31B**. Real Gemma inference remains an explicit separate step on suitable local hardware, and generated cases must receive independent review before performance claims.
