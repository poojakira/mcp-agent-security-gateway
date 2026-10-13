"""Security-negative regressions for stale/missing PDF with unchanged PNG."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from verify_artifacts import GIT, verify


class ArtifactIntegrityTests(unittest.TestCase):
    def setUp(self):
        if GIT is None:
            self.skipTest("Git unavailable")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "poster").mkdir()
        (self.root / "poster/verified_claims.json").write_text(
            json.dumps({"repository": "fixture"})
        )
        (self.root / "poster/poster.png").write_bytes(b"unchanged fixture PNG")
        (self.root / "poster/poster_36x48.pdf").write_bytes(b"fixture PDF")
        for command in [
            [GIT, "init", "-q"],
            [GIT, "add", "."],
            [
                GIT,
                "-c",
                "user.name=Evidence Fixture",
                "-c",
                "user.email=evidence@example.invalid",
                "commit",
                "-qm",
                "isolated artifact baseline",
            ],
        ]:
            subprocess.run(  # noqa: S603 - fixed git commands in an isolated fixture
                command,
                cwd=self.root,
                check=True,
                capture_output=True,
            )

    def test_changed_pdf_rejected_with_unchanged_png(self):
        self.assertTrue(verify(self.root))
        (self.root / "poster/poster_36x48.pdf").write_bytes(b"tampered fixture PDF")
        old = subprocess.run(  # noqa: S603 - resolved git with fixed read-only fixture paths
            [GIT, "diff", "--exit-code", "--", "poster/poster.png"],
            cwd=self.root,
            capture_output=True,
            check=False,
        )
        self.assertEqual(old.returncode, 0)  # old PNG-only gate missed the defect
        self.assertFalse(verify(self.root))

    def test_missing_pdf_rejected_with_unchanged_png(self):
        (self.root / "poster/poster_36x48.pdf").unlink()
        self.assertFalse(verify(self.root))


if __name__ == "__main__":
    unittest.main()
