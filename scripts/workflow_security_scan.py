from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PINNED_ACTION = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-fA-F]{40}$"
)


def scan_workflows() -> list[str]:
    failures: list[str] = []
    if not WORKFLOWS.is_dir():
        return ["missing .github/workflows directory"]

    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()

        if re.search(r"(?m)^\s*permissions:\s*write-all\s*$", text):
            failures.append(f"{rel}: write-all workflow permissions are forbidden")
        if re.search(r"(?m)^\s*pull_request_target:\s*$", text):
            failures.append(f"{rel}: pull_request_target is forbidden")
        if re.search(r"(?m)^\s*workflow_run:\s*$", text):
            failures.append(f"{rel}: workflow_run is forbidden")
        if re.search(r"curl\s+[^\n|]+\|\s*(?:ba)?sh", text, flags=re.IGNORECASE):
            failures.append(f"{rel}: pipe-to-shell execution is forbidden in workflows")
        if re.search(r"wget\s+[^\n|]+\|\s*(?:ba)?sh", text, flags=re.IGNORECASE):
            failures.append(f"{rel}: wget-to-shell execution is forbidden in workflows")

        for index, line in enumerate(lines):
            match = re.search(r"\buses:\s*([^\s#]+)", line)
            if not match:
                continue
            action = match.group(1)
            if action.startswith("./"):
                continue
            if not PINNED_ACTION.fullmatch(action):
                failures.append(
                    f"{rel}:{index + 1}: action is not pinned to a 40-char commit SHA: {action}"
                )

            if action.lower().startswith("actions/checkout@"):
                indent = re.match(r"^(\s*)", line).group(1)
                step_indent = indent[:-2] if len(indent) >= 2 else ""
                block_lines = [line]
                for following in lines[index + 1 :]:
                    if re.match(rf"^{re.escape(step_indent)}-\s", following):
                        break
                    block_lines.append(following)
                block = "\n".join(block_lines)
                if not re.search(r"(?m)^\s*persist-credentials:\s*false\s*$", block):
                    failures.append(
                        f"{rel}:{index + 1}: actions/checkout must set persist-credentials: false"
                    )

    return failures


def main() -> int:
    failures = scan_workflows()
    if failures:
        raise SystemExit("\n".join(sorted(set(failures))))
    print("workflow security policy verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
