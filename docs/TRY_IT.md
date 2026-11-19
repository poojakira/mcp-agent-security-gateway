# Browser testing access

## Free guided notebook

Open [this product's Colab notebook](https://colab.research.google.com/github/poojakira/mcp-agent-security-gateway/blob/codex/local-workbench-20261116/notebooks/try_product.ipynb). A Google account and available free CPU session are needed. Run the setup cell, choose a documented synthetic scenario, run the scenario cell, then rerun with a different scenario or execute the side-by-side cell. Expand JSON to inspect actual engine findings, configuration, input hashes and limitations. No output is prepopulated in the committed notebook.

The notebook uses normal inline notebook controls. It does not start a web server, tunnel, background job or publicly shared operator session. No user file, policy, credentials or PHI is requested. All inputs come from the checked-out `demo/adapter.py` fixtures. The runner calls the actual canonical engine and emits exact checkout provenance. The isolated temporary environment contains minimal dependencies, not the full application/test dependency set. It is not installed-wheel or production validation. The full local UI and its additional prerequisites remain documented in the README/runbook.

## Execution evidence

Locally executed setup/runner/scenario tests are distinguished from **Colab-hosted execution**, which is NOT VERIFIED unless a generated record explicitly identifies that environment. An opening notebook link is not proof of a working remote kernel. The generated [candidate assessment](https://github.com/poojakira/mcp-agent-security-gateway/tree/evidence/selected-branches-20261118/release-evidence/RELEASE_ASSESSMENT.md) and manifest record actual checks and source. Unsupported runtime/Python conditions must fail visibly; they are not clean scans. No universal safety or security guarantee follows from a synthetic example.

## Cost and access boundary

Use Colab's free CPU runtime. This notebook requests no subscription, GPU, purchased compute units, paid API, new API key, Drive mount, billing credential or external cloud resource. It cannot guarantee future third-party plan terms or resource availability. Review the current [Colab FAQ](https://research.google.com/colaboratory/faq.html). Do not upgrade or provide billing details to run this guide; use the local product if the free runtime is unavailable.

No Render service/database was created. Render was rejected for this task because free compute can still incur workspace bandwidth/build charges. Current Hugging Face documentation says new Docker/Gradio compute Spaces require a paid plan, so they are not this task's hosting alternative. No hosted full-application URL is claimed. Public full-product deployment still needs its own security, privacy, operational and cost acceptance.

## Local equivalent

From the reviewed checkout, create a dedicated venv, install `demo/requirements-notebook.txt`, then run:

```sh
python -I demo/notebook_runner.py SCENARIO
```

Replace `SCENARIO` with one exact identifier listed in the notebook's dropdown/adapter specification. The runner rejects unknown identifiers and loads only this checkout's fixed engine code. Compare the resulting source SHA and CLEAN/DIRTY state; do not relabel dirty or UNKNOWN provenance as clean.

## Architecture viewer publication

`docs/index.html` provides a static zoom/pan architecture viewer with larger overview text and links to the inline notebook. Its local browser checks are recorded separately. GitHub Pages configuration was attempted through the existing integration and returned `HTTP 403: Resource not accessible by integration`; no hosted Pages URL is claimed. The owner can enable Pages from the retained candidate branch and `/docs` using normal repository settings, without creating an API key or another branch.
