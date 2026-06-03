from __future__ import annotations

from pathlib import Path
import json
import hashlib
import tarfile
import tempfile
import unittest

from system.scaffold_guard.engine import ScaffoldEngine, ScaffoldError
from system.scaffold_guard.locks import verify_template_lock, write_template_lock
from system.scaffold_guard.policy import get_policy_profile
from system.scaffold_guard.registry import load_registry, search_registry
from system.scaffold_guard.source_adapters import (
    RemoteSourcePolicy,
    parse_github_archive_ref,
    resolve_github_archive,
)
from system.scaffold_guard.trace import write_materialization_trace


class ScaffoldEngineTests(unittest.TestCase):
    def test_preview_allows_clean_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            template.mkdir()
            (template / "README.md").write_text("hello\n", encoding="utf-8")

            report = ScaffoldEngine().preview(template)

            self.assertTrue(report.allowed)
            self.assertEqual(report.file_count, 1)
            self.assertEqual(report.files[0].relative_path, "README.md")

    def test_preview_blocks_possible_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            template.mkdir()
            blocked_value = "_".join(("API", "KEY")) + "=" + "abcdef1234567890" + "\n"
            (template / ".env").write_text(blocked_value, encoding="utf-8")

            report = ScaffoldEngine().preview(template)

            self.assertFalse(report.allowed)
            self.assertTrue(report.findings[0].code.startswith("secret_"))

    def test_materialize_writes_manifest_and_audit_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            dest = tmp_path / "dest"
            template.mkdir()
            (template / "app.py").write_text("print('ok')\n", encoding="utf-8")

            result = ScaffoldEngine().materialize(template, dest)
            audit = ScaffoldEngine().audit(dest)

            self.assertEqual(result.file_count, 1)
            self.assertTrue((dest / "app.py").exists())
            self.assertTrue(Path(result.manifest_path).exists())
            self.assertTrue(audit.passed)

    def test_materialize_skips_blocked_junk_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            dest = tmp_path / "dest"
            (template / ".git").mkdir(parents=True)
            (template / "__pycache__").mkdir()
            (template / "node_modules" / "pkg").mkdir(parents=True)
            (template / "README.md").write_text("clean\n", encoding="utf-8")
            (template / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (template / "__pycache__" / "junk.pyc").write_bytes(b"junk")
            (template / "node_modules" / "pkg" / "index.js").write_text("bad\n", encoding="utf-8")

            result = ScaffoldEngine().materialize(template, dest)

            self.assertEqual(result.file_count, 1)
            self.assertTrue((dest / "README.md").exists())
            self.assertFalse((dest / ".git").exists())
            self.assertFalse((dest / "__pycache__").exists())
            self.assertFalse((dest / "node_modules").exists())

    def test_audit_detects_changed_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            dest = tmp_path / "dest"
            template.mkdir()
            (template / "app.py").write_text("print('ok')\n", encoding="utf-8")
            ScaffoldEngine().materialize(template, dest)

            (dest / "app.py").write_text("print('changed')\n", encoding="utf-8")
            audit = ScaffoldEngine().audit(dest)

            self.assertFalse(audit.passed)
            self.assertEqual(audit.changed, ("app.py",))

    def test_audit_detects_extra_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            dest = tmp_path / "dest"
            template.mkdir()
            (template / "app.py").write_text("print('ok')\n", encoding="utf-8")
            ScaffoldEngine().materialize(template, dest)

            (dest / "unexpected.txt").write_text("extra\n", encoding="utf-8")
            audit = ScaffoldEngine().audit(dest)

            self.assertFalse(audit.passed)
            self.assertEqual(audit.extra, ("unexpected.txt",))

    def test_verify_blocks_non_empty_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            dest = tmp_path / "dest"
            template.mkdir()
            dest.mkdir()
            (template / "app.py").write_text("print('ok')\n", encoding="utf-8")
            (dest / "existing.txt").write_text("existing\n", encoding="utf-8")

            report = ScaffoldEngine().verify(template, dest)

            self.assertFalse(report.allowed)
            self.assertTrue(
                any(finding.code == "destination_not_empty" for finding in report.preview.findings)
            )

    def test_archive_source_materializes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            template.mkdir()
            (template / "README.md").write_text("archived\n", encoding="utf-8")
            archive = tmp_path / "template.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                handle.add(template, arcname="template")

            dest = tmp_path / "dest"
            result = ScaffoldEngine().materialize(archive, dest)

            self.assertEqual(result.file_count, 1)
            self.assertEqual((dest / "README.md").read_text(encoding="utf-8"), "archived\n")

    def test_archive_unsafe_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = tmp_path / "unsafe.tar"
            payload = tmp_path / "payload.txt"
            payload.write_text("bad\n", encoding="utf-8")
            with tarfile.open(archive, "w") as handle:
                handle.add(payload, arcname="../escape.txt")

            with self.assertRaises(ScaffoldError):
                ScaffoldEngine().preview(archive)

    def test_preview_blocks_symlinked_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            external = tmp_path / "external"
            template.mkdir()
            external.mkdir()
            (external / "secret.txt").write_text("outside\n", encoding="utf-8")
            (template / "linked").symlink_to(external, target_is_directory=True)

            report = ScaffoldEngine().preview(template)

            self.assertFalse(report.allowed)
            self.assertTrue(any(finding.code == "symlink_blocked" for finding in report.findings))

    def test_preview_does_not_write_to_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            dest = tmp_path / "dest"
            template.mkdir()
            (template / "README.md").write_text("preview only\n", encoding="utf-8")

            report = ScaffoldEngine().preview(template)

            self.assertTrue(report.allowed)
            self.assertFalse(dest.exists())

    def test_audit_reports_tampered_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            dest = tmp_path / "dest"
            template.mkdir()
            (template / "app.py").write_text("print('ok')\n", encoding="utf-8")
            ScaffoldEngine().materialize(template, dest)

            (dest / ".scaffold_guard" / "manifest.json").write_text("{bad json", encoding="utf-8")
            audit = ScaffoldEngine().audit(dest)

            self.assertFalse(audit.passed)
            self.assertTrue(any(finding.code == "manifest_invalid" for finding in audit.findings))

    def test_github_ref_parser_requires_explicit_ref(self) -> None:
        parsed = parse_github_archive_ref("github:Rich-Harris/degit#main")

        self.assertEqual(parsed.repo_key, "Rich-Harris/degit")
        self.assertEqual(parsed.archive_url, "https://github.com/Rich-Harris/degit/archive/main.tar.gz")

        with self.assertRaises(ScaffoldError):
            parse_github_archive_ref("github:Rich-Harris/degit")

    def test_github_archive_blocks_unapproved_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = RemoteSourcePolicy.from_allowed(["approved/repo"], network_enabled=True)

            with self.assertRaises(ScaffoldError):
                resolve_github_archive("github:Rich-Harris/degit#main", policy=policy, work_dir=Path(tmp))

    def test_github_archive_requires_network_enabled_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = RemoteSourcePolicy.from_allowed(["Rich-Harris/degit"])

            with self.assertRaises(ScaffoldError):
                resolve_github_archive("github:Rich-Harris/degit#main", policy=policy, work_dir=Path(tmp))

    def test_commercial_policy_requires_remote_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile = get_policy_profile("commercial")
            policy = RemoteSourcePolicy.from_allowed(
                ["Rich-Harris/degit"],
                network_enabled=True,
                profile=profile,
            )

            with self.assertRaises(ScaffoldError):
                resolve_github_archive("github:Rich-Harris/degit#main", policy=policy, work_dir=Path(tmp))

    def test_github_archive_checksum_mismatch_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            policy = RemoteSourcePolicy.from_allowed(
                ["Rich-Harris/degit"],
                expected_sha256="0" * 64,
                network_enabled=True,
            )

            def fake_downloader(url: str, destination: Path, max_bytes: int) -> None:
                del url, max_bytes
                destination.write_bytes(b"not the expected archive")

            with self.assertRaises(ScaffoldError):
                resolve_github_archive(
                    "github:Rich-Harris/degit#main",
                    policy=policy,
                    work_dir=tmp_path,
                    downloader=fake_downloader,
                )

    def test_github_archive_materializes_with_manifest_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive_payload = tmp_path / "payload.tar.gz"
            template = tmp_path / "template"
            template.mkdir()
            (template / "README.md").write_text("remote archive\n", encoding="utf-8")
            with tarfile.open(archive_payload, "w:gz") as handle:
                handle.add(template, arcname="template")
            expected_sha256 = hashlib.sha256(archive_payload.read_bytes()).hexdigest()
            policy = RemoteSourcePolicy.from_allowed(
                ["Rich-Harris/degit"],
                expected_sha256=expected_sha256,
                network_enabled=True,
            )

            def fake_downloader(url: str, destination: Path, max_bytes: int) -> None:
                self.assertEqual(url, "https://github.com/Rich-Harris/degit/archive/main.tar.gz")
                self.assertGreaterEqual(max_bytes, archive_payload.stat().st_size)
                destination.write_bytes(archive_payload.read_bytes())

            remote = resolve_github_archive(
                "github:Rich-Harris/degit#main",
                policy=policy,
                work_dir=tmp_path / "remote",
                downloader=fake_downloader,
            )
            dest = tmp_path / "dest"
            result = ScaffoldEngine().materialize(remote.archive_path, dest, provenance=remote.provenance)
            manifest = json.loads((dest / ".scaffold_guard" / "manifest.json").read_text(encoding="utf-8"))

            self.assertEqual(result.provenance["repo_key"], "Rich-Harris/degit")
            self.assertEqual(manifest["provenance"]["archive_sha256"], expected_sha256)
            self.assertTrue(ScaffoldEngine().audit(dest).passed)

    def test_signed_template_lock_verifies_and_detects_source_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            lock_path = tmp_path / "template.scaffold-lock.json"
            template.mkdir()
            (template / "README.md").write_text("locked\n", encoding="utf-8")

            payload = write_template_lock(
                template,
                lock_path,
                engine=ScaffoldEngine(),
                policy_profile=get_policy_profile("commercial"),
                signing_key="test-signing-key",
            )
            verified = verify_template_lock(
                template,
                lock_path,
                engine=ScaffoldEngine(),
                signing_key="test-signing-key",
            )

            self.assertEqual(payload["signature"], verified["signature"])
            self.assertEqual(verified["policy_profile"]["name"], "commercial")

            (template / "README.md").write_text("changed\n", encoding="utf-8")
            with self.assertRaises(ScaffoldError):
                verify_template_lock(
                    template,
                    lock_path,
                    engine=ScaffoldEngine(),
                    signing_key="test-signing-key",
                )

    def test_signed_template_lock_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            lock_path = tmp_path / "template.scaffold-lock.json"
            template.mkdir()
            (template / "README.md").write_text("locked\n", encoding="utf-8")
            write_template_lock(
                template,
                lock_path,
                engine=ScaffoldEngine(),
                policy_profile=get_policy_profile("enterprise"),
                signing_key="test-signing-key",
            )

            payload = json.loads(lock_path.read_text(encoding="utf-8"))
            payload["policy_profile"]["name"] = "dev"
            lock_path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaises(ScaffoldError):
                verify_template_lock(
                    template,
                    lock_path,
                    engine=ScaffoldEngine(),
                    signing_key="test-signing-key",
                )

    def test_registry_validates_and_searches_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry_path = Path(tmp) / "registry.json"
            registry_path.write_text(
                json.dumps(
                    {
                        "templates": [
                            {
                                "checksum_sha256": "a" * 64,
                                "id": "corp-web",
                                "intended_use": "Corporate website baseline",
                                "owner": "platform",
                                "policy_profile": "commercial",
                                "source": "github:owner/repo#main",
                                "source_type": "github_archive",
                                "tags": ["web", "corporate"],
                                "version": "1.0.0",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = load_registry(registry_path)
            matches = search_registry(report, tag="web", policy_profile="commercial")

            self.assertTrue(report.valid)
            self.assertEqual(matches[0].template_id, "corp-web")

    def test_registry_blocks_malformed_archive_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry_path = Path(tmp) / "registry.json"
            registry_path.write_text(
                json.dumps(
                    {
                        "templates": [
                            {
                                "id": "bad",
                                "intended_use": "Missing checksum",
                                "owner": "platform",
                                "policy_profile": "commercial",
                                "source": "github:owner/repo#main",
                                "source_type": "github_archive",
                                "tags": ["web"],
                                "version": "1.0.0",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = load_registry(registry_path)

            self.assertFalse(report.valid)
            self.assertTrue(any("checksum_sha256" in finding for finding in report.findings))

    def test_materialization_trace_exports_request_context_and_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            template = tmp_path / "template"
            dest = tmp_path / "dest"
            trace_path = tmp_path / "trace.json"
            template.mkdir()
            (template / "README.md").write_text("trace\n", encoding="utf-8")
            engine = ScaffoldEngine()

            report = engine.materialize(template, dest)
            audit = engine.audit(dest)
            trace = write_materialization_trace(
                trace_path,
                report,
                requester="unit-test",
                policy_profile=get_policy_profile("commercial"),
                audit=audit,
                directive="create test scaffold",
            )
            saved = json.loads(trace_path.read_text(encoding="utf-8"))

            self.assertEqual(trace["requester"], "unit-test")
            self.assertEqual(saved["policy_profile"]["name"], "commercial")
            self.assertTrue(saved["audit"]["passed"])


if __name__ == "__main__":
    unittest.main()
