"""Mocked synthetic pin-rotation tests; no provider requests or PDF authoring."""
import copy
from email.parser import BytesParser
import email.policy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "vault_dummy_rotation", Path(__file__).resolve().parents[1] / "scripts/rotate_vault_dummy.py")
rotation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rotation)
release = rotation.release
BASE = "11111111-1111-4111-8111-111111111111"
NEW = "22222222-2222-4222-8222-222222222222"
CANDIDATE = "33333333-3333-4333-8333-333333333333"
DRIFT = "44444444-4444-4444-8444-444444444444"
NOW = 1791637200000
SOURCE = b"export default {fetch(){return new Response('synthetic source')}}"
PDF = b"%PDF-1.7\nsynthetic mocked QA input; not a authored PDF\n%%EOF\n"
RECIPIENT, SENDER = "synthetic-recipient@example.test", "synthetic-sender@example.test"
SECRET_MARKER = "synthetic-secret-never-retained"


def bindings():
    rows = [{"name": name, "type": kind} for name, kind in release.BINDING_TYPES.items()]
    by_name = {row["name"]: row for row in rows}
    for name, value in release.FIXED_VARS.items():
        by_name[name]["text"] = value
    by_name["VAULT_DOCUMENTS"]["bucket_name"] = release.BUCKET
    by_name["VAULT"].update(namespace_id=release.NAMESPACE, class_name="VaultDocument")
    by_name["NOTIFY_EMAIL"].update(destination_address=RECIPIENT, allowed_sender_addresses=[SENDER])
    for row in rows:
        if row["type"] == "secret_text":
            row["text"] = SECRET_MARKER  # Unexpected fields must never enter evidence or upload.
    return rows


class FakeAPI:
    def __init__(self, failure=None, settings_are_active=False):
        self.active, self.latest = BASE, BASE
        self.rows = {BASE: bindings()}
        self.calls, self.posts = [], []
        self.failure, self.settings_are_active = failure, settings_are_active
        self.settings_reads = 0
        self.runtime = {"migration_tag": "v1-vault", "compatibility_date": "2026-01-12",
                        "compatibility_flags": ["nodejs_compat"], "usage_model": "standard",
                        "limits": {"cpu_ms": 30000}}
        self.source = SOURCE
        self.uploaded_source = None
        self.metadata = None

    def __call__(self, path, method="GET", data=None, content_type=None, raw=False):
        self.calls.append((method, path))
        if method == "POST":
            self.posts.append((path, data))
            if path == release.SCRIPT + "/versions":
                if self.failure == "upload_timeout":
                    self.latest = NEW  # Remote success is unknown; never repeat the upload.
                    raise release.SafeFailure("api_transport_unknown")
                msg = BytesParser(policy=email.policy.default).parsebytes(
                    ("Content-Type: " + content_type + "\r\nMIME-Version: 1.0\r\n\r\n").encode() + data)
                parts = list(msg.iter_parts())
                self.metadata = json.loads(parts[0].get_payload(decode=True))
                self.uploaded_source = parts[1].get_payload(decode=True)
                old = self.rows[BASE]
                self.rows[NEW] = [copy.deepcopy(row) for row in old if row["type"] in self.metadata["keep_bindings"]]
                self.rows[NEW].extend(copy.deepcopy(self.metadata["bindings"]))
                if self.failure == "wrong_new_pin":
                    next(row for row in self.rows[NEW] if row["name"] == "DUMMY_RECORD_SHA256")["text"] = "f" * 64
                if self.failure == "missing_secret_binding":
                    self.rows[NEW] = [row for row in self.rows[NEW] if row["name"] != "VAULT_OWNER_SUB"]
                if self.failure == "canary_binding_added":
                    self.rows[NEW].append({"name": "CANARY_SERVICE", "type": "service", "service": "kanariya"})
                if self.failure == "changed_do_namespace":
                    next(row for row in self.rows[NEW] if row["name"] == "VAULT")["namespace_id"] = "unexpected"
                self.latest = NEW
                return {"id": NEW}
            if path == release.SCRIPT + "/deployments":
                self.active = NEW
                if self.failure == "activation_timeout":
                    raise release.SafeFailure("api_transport_unknown")
                return {"id": "synthetic-deployment"}
            raise AssertionError("unexpected mutation")
        if path == release.SCRIPT + "/deployments":
            rows = [{"version_id": self.active, "percentage": 100}]
            if self.failure == "split":
                rows = [{"version_id": BASE, "percentage": 50}, {"version_id": NEW, "percentage": 50}]
            return {"deployments": [{"versions": rows}]}
        if path == release.SCRIPT + "/versions":
            version = DRIFT if self.failure == "latest_not_active" else self.latest
            return {"items": [{"id": version}]}
        if path.startswith(release.SCRIPT + "/versions/"):
            version = path.rsplit("/", 1)[1]
            rows = copy.deepcopy(self.rows[version])
            runtime = copy.deepcopy(self.runtime)
            etag = release.digest(SOURCE)
            handlers = ["VaultDocument"]
            if self.latest == NEW and version == NEW:
                if self.failure == "new_runtime":
                    runtime["compatibility_flags"].append("unexpected_flag")
                if self.failure == "new_version_source":
                    etag = release.digest(b"unexpected source even if /content/v2 is stale")
                if self.failure == "new_handlers":
                    handlers = ["UnexpectedDocument"]
            return {"id": version, "resources": {"bindings": rows, "script_runtime": runtime,
                    "script": {"etag": etag, "handlers": ["fetch"], "named_handlers": handlers}}}
        if path == release.SCRIPT + "/settings":
            if self.failure == "permission":
                error = release.SafeFailure("api_http_403")
                error.http_status, error.api_codes, error.api_resource = 403, [10000], "worker_or_zone_metadata"
                raise error
            self.settings_reads += 1
            value = {"bindings": copy.deepcopy(self.rows[self.active if self.settings_are_active else self.latest]),
                     "compatibility_date": "2026-01-12", "compatibility_flags": ["nodejs_compat"],
                     "observability": {"enabled": False}}
            if self.failure == "preupload_drift" and self.settings_reads >= 2:
                value["observability"]["enabled"] = True
            if self.failure == "postactivation_drift" and self.active == NEW:
                value["observability"]["enabled"] = True
            if self.failure == "afterupload_settings_other_pin" and self.latest == NEW:
                next(row for row in value["bindings"] if row["name"] == "DUMMY_DOCUMENT_ID")["text"] = DRIFT
            if self.failure == "preactivation_drift" and self.latest == NEW and self.settings_reads >= 4:
                self.latest = DRIFT
            return value
        if path == release.SCRIPT + "/content/v2":
            if self.failure == "wrong_source" and self.latest == NEW:
                self.source = b"unexpected source"
            encoded = (b'--synthetic\r\nContent-Disposition: form-data; name="worker.js"; filename="worker.js"\r\n'
                       b'Content-Type: application/javascript+module\r\n\r\n' + self.source + b"\r\n--synthetic--\r\n")
            return "multipart/form-data; boundary=synthetic", encoded
        if path == release.SCRIPT + "/subdomain":
            return {"enabled": self.failure == "public_endpoint", "previews_enabled": False}
        if path == f"/accounts/{release.ACCOUNT}/workers/domains":
            return [{"service": release.WORKER, "hostname": "vault.toppymicros.com", "environment": "production"}]
        if path.startswith("/zones?"):
            return [{"id": release.ZONE, "account": {"id": release.ACCOUNT}}]
        if path == f"/zones/{release.ZONE}/workers/routes":
            return [{"script": release.WORKER}] if self.failure == "route" else []
        raise AssertionError("unexpected read: " + path)


class DummyRotationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.plan_path, self.pdf_path = self.directory / "plan.json", self.directory / "final.pdf"
        self.qa_path, self.report_path = self.directory / "qa-report.json", self.directory / "rotation.json"
        self.plan = {"version": 1, "status": "prepared_not_active", "id": CANDIDATE,
                     "currentDocumentId": release.FIXED_VARS["DUMMY_DOCUMENT_ID"],
                     "currentRecordSha256": release.FIXED_VARS["DUMMY_RECORD_SHA256"],
                     "recordSha256": release.digest(b"synthetic encrypted replacement"),
                     "preparedSha256": release.digest(PDF), "sourceSha256": release.digest(b"synthetic source PDF"),
                     "watermarkEnabled": True, "expiresAt": NOW + 86400000, "authMode": "password",
                     "registryRevision": 2, "createdAt": NOW - 1000}
        self.pdf_path.write_bytes(PDF)
        images = []
        for renderer in rotation.RENDERERS:
            for page in (1, 2):
                path = f"renders/{renderer}/page-{page}.png"
                target = self.directory / path
                target.parent.mkdir(parents=True, exist_ok=True)
                content = f"mocked synthetic {renderer} page {page}".encode()
                target.write_bytes(content)
                images.append({"path": path, "sha256": release.digest(content), "renderer": renderer})
        checks = {name: {"passed": True} for name in ("synthetic_content", "no_interactive_content",
                  "no_pdf_open_callback_or_external_reference_objects", "poppler_nonblank", "pdfkit_nonblank", "pdfium_nonblank")}
        checks.update(expected_page_count={"passed": True, "page_count": 2},
                      source_bytes_unchanged={"passed": True, "final_sha256": release.digest(PDF)},
                      recipient_raster_on_every_page={"passed": True, "pages_checked": 2},
                      visual_review={"passed": True, "artifact_and_image_hashes_match": True, "record": "visual-review.json"})
        for name in ("qpdf_structure", "ghostscript_structure"):
            checks[name] = {"passed": True, "exit_code": 0, "structural_warnings": []}
        for renderer in rotation.RENDERERS:
            checks[renderer + "_all_pages"] = {"passed": True, "rendered_pages": 2, "exit_code": 0}
        self.qa = {"schema_version": 1, "status": "verified", "sha256": release.digest(PDF), "bytes": len(PDF),
                   "source": "Entirely synthetic; no real CV or personal data was read.", "warnings": [],
                   "checks": checks, "renderers": {name: {"version": "mocked synthetic test"} for name in rotation.RENDERERS},
                   "images": images, "not_verified": ["User visual confirmation", "Native viewer UI", "Notification delivery"]}
        (self.directory / "visual-review.json").write_text(json.dumps({"passed": True, "pdf_sha256": release.digest(PDF),
            "images": [{"path": row["path"], "sha256": row["sha256"]} for row in images]}))
        self.save_inputs()
        for target, name, value in ((release, "RECIPIENT_SHA256", release.digest(RECIPIENT.encode())),
                                    (release, "SENDER_SHA256", release.digest(SENDER.encode())),
                                    (rotation, "now_ms", lambda: NOW)):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def save_inputs(self):
        self.plan_path.write_text(json.dumps(self.plan, indent=2) + "\n")
        self.qa_path.write_text(json.dumps(self.qa))

    def run_rotation(self, api=None, execute=False, approve=None):
        api = api or FakeAPI()
        output = io.StringIO()
        args = ["--plan", str(self.plan_path), "--pdf", str(self.pdf_path),
                "--qa-report", str(self.qa_path), "--report", str(self.report_path)]
        if execute:
            args.append("--execute")
        if approve is not None:
            args.extend(["--approve", approve])
        with patch.object(rotation, "API", return_value=api) as constructor, patch("sys.stdout", output):
            status = rotation.main(args)
        return status, api, constructor, output.getvalue()

    def approved(self, api=None):
        return self.run_rotation(api, execute=True, approve=release.digest(self.plan_path.read_bytes()))

    def report(self):
        return json.loads(self.report_path.read_text())

    def test_default_is_read_only_and_does_not_claim_private_object_or_user_confirmation(self):
        status, api, _, output = self.run_rotation()
        self.assertEqual(status, 0)
        self.assertEqual(api.posts, [])
        report = self.report()
        self.assertEqual(report["status"], "reviewed_not_executed")
        self.assertEqual(report["remoteMutations"], 0)
        self.assertEqual(report["planSha256"], release.digest(self.plan_path.read_bytes()))
        self.assertFalse(report["privateReplacementObjectVerified"])
        self.assertFalse(report["serverSideCompareAndSwap"])
        self.assertEqual(report["r2ApiRequests"], 0)
        self.assertFalse(any("/r2/" in path for _, path in api.calls))
        self.assertEqual(self.report_path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("User visual confirmation", output)

    def test_approved_execution_preserves_source_and_thirteen_other_bindings(self):
        original = copy.deepcopy(release.FIXED_VARS)
        status, api, _, output = self.approved()
        self.assertEqual(status, 0)
        self.assertEqual(api.active, NEW)
        self.assertEqual(api.uploaded_source, SOURCE)
        self.assertEqual(len(api.posts), 2)
        self.assertEqual(api.metadata["keep_bindings"], ["durable_object_namespace", "r2_bucket", "secret_text", "send_email"])
        self.assertEqual(len(api.metadata["bindings"]), 7)
        self.assertNotIn("plain_text", api.metadata["keep_bindings"])
        self.assertNotIn("migration_tag", api.metadata)
        self.assertNotIn("migrations", api.metadata)
        self.assertEqual(api.metadata["limits"], {"cpu_ms": 30000})
        old = {row["name"]: row for row in api.rows[BASE]}
        new = {row["name"]: row for row in api.rows[NEW]}
        self.assertEqual(set(old), set(new))
        for name in set(old) - rotation.PIN_NAMES:
            self.assertEqual(new[name], old[name])
        self.assertEqual(new["DUMMY_DOCUMENT_ID"]["text"], CANDIDATE)
        self.assertEqual(new["DUMMY_RECORD_SHA256"]["text"], self.plan["recordSha256"])
        self.assertEqual(release.FIXED_VARS, original)
        self.assertEqual(api.posts[1][1], {"strategy": "percentage", "versions": [{"version_id": NEW, "percentage": 100}]})
        self.assertEqual(self.report()["remoteMutations"], 2)
        self.assertTrue(self.report()["sourceOnlyDeployHelperNeedsApprovedPinUpdate"])
        for marker in (SECRET_MARKER, RECIPIENT, SENDER):
            self.assertNotIn(marker, output + self.report_path.read_text() + str(api.metadata))
        self.assertFalse(any("/r2/" in path for _, path in api.calls))

    def test_settings_endpoint_may_describe_active_version_during_staging(self):
        self.assertEqual(self.approved(FakeAPI(settings_are_active=True))[0], 0)

    def test_missing_or_wrong_approval_prevents_even_provider_preflight(self):
        for approval in (None, "f" * 64):
            with self.subTest(approval=approval):
                status, api, constructor, _ = self.run_rotation(execute=True, approve=approval)
                self.assertEqual(status, 1)
                constructor.assert_not_called()
                self.assertEqual(api.calls, [])

    def test_approval_is_of_exact_file_bytes_not_parsed_equivalent_json(self):
        approval = release.digest(self.plan_path.read_bytes())
        self.plan_path.write_text(json.dumps(self.plan, separators=(",", ":")))
        self.assertEqual(self.run_rotation(execute=True, approve=approval)[0], 1)

    def test_private_or_extra_plan_fields_are_rejected_without_echo(self):
        self.plan["recipientName"] = SECRET_MARKER
        self.save_inputs()
        status, api, constructor, output = self.approved()
        self.assertEqual(status, 1)
        constructor.assert_not_called()
        self.assertEqual(api.calls, [])
        self.assertNotIn(SECRET_MARKER, output)

    def test_duplicate_plan_keys_are_rejected(self):
        self.plan_path.write_text(self.plan_path.read_text().replace('"version": 1', '"version": 1, "version": 1'))
        self.assertEqual(self.run_rotation()[0], 1)

    def test_invalid_current_pins_and_auth_changes_are_rejected(self):
        original = copy.deepcopy(self.plan)
        for name, value in (("currentDocumentId", DRIFT), ("currentRecordSha256", "f" * 64),
                            ("authMode", "access"), ("version", True), ("watermarkEnabled", 1),
                            ("registryRevision", True), ("registryRevision", 1), ("createdAt", NOW + 1),
                            ("expiresAt", NOW), ("id", self.plan["currentDocumentId"]),
                            ("recordSha256", self.plan["currentRecordSha256"])):
            with self.subTest(field=name, value=value):
                self.plan = {**original, name: value}
                self.save_inputs()
                status, _, constructor, _ = self.run_rotation()
                self.assertEqual(status, 1)
                constructor.assert_not_called()

    def test_changed_final_pdf_is_rejected_without_provider_requests(self):
        self.pdf_path.write_bytes(PDF + b"changed")
        status, _, constructor, _ = self.run_rotation()
        self.assertEqual(status, 1)
        constructor.assert_not_called()

    def test_pdf_over_runtime_one_mib_limit_is_rejected_before_provider_preflight(self):
        oversized = PDF + b" " * (1024 * 1024 + 1 - len(PDF))
        self.pdf_path.write_bytes(oversized)
        expected = release.digest(oversized)
        self.plan["preparedSha256"] = expected
        self.qa.update(sha256=expected, bytes=len(oversized))
        self.qa["checks"]["source_bytes_unchanged"]["final_sha256"] = expected
        self.save_inputs()
        status, api, constructor, output = self.approved()
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output)["reason"], "final_pdf_size_invalid")
        constructor.assert_not_called()
        self.assertEqual(api.calls, [])

    def test_pdf_over_viewer_twenty_page_limit_is_rejected_before_provider_preflight(self):
        self.qa["checks"]["expected_page_count"]["page_count"] = 21
        for renderer in rotation.RENDERERS:
            self.qa["checks"][renderer + "_all_pages"]["rendered_pages"] = 21
        self.qa["checks"]["recipient_raster_on_every_page"]["pages_checked"] = 21
        self.save_inputs()
        status, api, constructor, output = self.approved()
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output)["reason"], "all_page_qa_required")
        constructor.assert_not_called()
        self.assertEqual(api.calls, [])

    def test_same_source_input_hash_is_not_a_substitute_for_exact_prepared_pdf(self):
        self.plan["preparedSha256"] = self.plan["sourceSha256"]
        self.save_inputs()
        self.assertEqual(self.run_rotation()[0], 1)

    def test_structural_warnings_nonzero_exit_or_missing_renderer_stop(self):
        original = copy.deepcopy(self.qa)
        cases = (("qpdf_structure", "structural_warnings", ["repaired"]),
                 ("ghostscript_structure", "exit_code", 1), ("qpdf_structure", "exit_code", False),
                 ("pdfkit_all_pages", "rendered_pages", 1), ("pdfium_all_pages", "passed", False),
                 ("visual_review", "artifact_and_image_hashes_match", False))
        for name, field, value in cases:
            with self.subTest(check=name, field=field):
                self.qa = copy.deepcopy(original)
                self.qa["checks"][name][field] = value
                self.save_inputs()
                status, _, constructor, _ = self.run_rotation()
                self.assertEqual(status, 1)
                constructor.assert_not_called()
        self.qa = copy.deepcopy(original)
        del self.qa["renderers"]["pdfkit"]
        self.save_inputs()
        self.assertEqual(self.run_rotation()[0], 1)

    def test_claimed_verified_status_does_not_override_failed_or_missing_checks(self):
        del self.qa["checks"]["synthetic_content"]
        self.save_inputs()
        self.assertEqual(self.run_rotation()[0], 1)

    def test_qa_requires_synthetic_provenance(self):
        self.qa["source"] = "unknown"
        self.save_inputs()
        self.assertEqual(self.run_rotation()[0], 1)

    def test_changed_or_missing_page_images_stop(self):
        target = self.directory / self.qa["images"][0]["path"]
        target.write_bytes(b"changed synthetic image")
        self.assertEqual(self.run_rotation()[0], 1)

    def test_renderer_counts_must_cover_every_page(self):
        self.qa["images"][0]["renderer"] = "pdfium"
        self.save_inputs()
        self.assertEqual(self.run_rotation()[0], 1)

    def test_visual_review_must_bind_exact_pdf_and_image_hashes(self):
        path = self.directory / "visual-review.json"
        value = json.loads(path.read_text())
        value["pdf_sha256"] = "f" * 64
        path.write_text(json.dumps(value))
        self.assertEqual(self.run_rotation()[0], 1)

    def test_symlink_and_escaping_qa_artifacts_are_rejected(self):
        target = self.directory / "image-target.png"
        target.write_bytes(b"unrelated image")
        image = self.directory / self.qa["images"][0]["path"]
        image.unlink()
        image.symlink_to(target)
        self.assertEqual(self.run_rotation()[0], 1)
        self.qa["images"][0]["path"] = "../escape.png"
        self.save_inputs()
        self.assertEqual(self.run_rotation()[0], 1)

    def test_plan_symlink_and_existing_report_preserve_local_files(self):
        target = self.directory / "plan-target.json"
        self.plan_path.rename(target)
        self.plan_path.symlink_to(target)
        self.assertEqual(self.run_rotation()[0], 1)
        self.plan_path.unlink()
        target.rename(self.plan_path)
        self.report_path.write_text("unrelated local work")
        status, api, constructor, _ = self.run_rotation()
        self.assertEqual(status, 1)
        constructor.assert_not_called()
        self.assertEqual(api.calls, [])
        self.assertEqual(self.report_path.read_text(), "unrelated local work")

    def test_preflight_configuration_and_permission_drift_prevent_upload(self):
        for failure in ("permission", "split", "latest_not_active", "preupload_drift", "public_endpoint", "route"):
            with self.subTest(failure=failure):
                if self.report_path.exists():
                    self.report_path.unlink()
                status, api, _, _ = self.approved(FakeAPI(failure))
                self.assertEqual(status, 1)
                self.assertEqual(api.posts, [])

    def test_any_changed_binding_runtime_export_or_source_blocks_activation(self):
        for failure in ("wrong_new_pin", "missing_secret_binding", "canary_binding_added", "changed_do_namespace",
                        "new_runtime", "new_handlers", "new_version_source", "wrong_source", "afterupload_settings_other_pin",
                        "preactivation_drift"):
            with self.subTest(failure=failure):
                if self.report_path.exists():
                    self.report_path.unlink()
                status, api, _, _ = self.approved(FakeAPI(failure))
                self.assertEqual(status, 1)
                self.assertEqual(len(api.posts), 1)
                self.assertEqual(api.active, BASE)
                self.assertEqual(self.report()["remoteMutations"], 1)

    def test_uncertain_upload_never_retries_or_activates(self):
        status, api, _, _ = self.approved(FakeAPI("upload_timeout"))
        self.assertEqual(status, 1)
        self.assertEqual(len(api.posts), 1)
        self.assertEqual(api.active, BASE)
        self.assertIsNone(self.report()["remoteMutations"])
        self.assertEqual(self.report()["phase"], "upload_attempt_started")

    def test_uncertain_activation_never_retries_or_rolls_back(self):
        status, api, _, _ = self.approved(FakeAPI("activation_timeout"))
        self.assertEqual(status, 1)
        self.assertEqual(len(api.posts), 2)
        self.assertIsNone(self.report()["remoteMutations"])
        self.assertEqual(self.report()["phase"], "activation_attempt_started")
        self.assertIsNone(self.report()["sourceOnlyDeployHelperNeedsApprovedPinUpdate"])

    def test_failed_final_readback_does_not_claim_completed_rotation(self):
        status, api, _, _ = self.approved(FakeAPI("postactivation_drift"))
        self.assertEqual(status, 1)
        self.assertEqual(len(api.posts), 2)
        self.assertNotEqual(self.report()["status"], "passed")
        self.assertEqual(self.report()["remoteMutations"], 2)

    def test_expiry_during_preflight_prevents_upload(self):
        calls = [NOW, NOW, NOW + 86400000]
        with patch.object(rotation, "now_ms", side_effect=calls):
            status, api, _, _ = self.approved()
        self.assertEqual(status, 1)
        self.assertEqual(api.posts, [])

    def test_expiry_after_upload_prevents_activation(self):
        calls = [NOW, NOW, NOW, NOW, NOW + 86400000]
        with patch.object(rotation, "now_ms", side_effect=calls):
            status, api, _, _ = self.approved()
        self.assertEqual(status, 1)
        self.assertEqual(len(api.posts), 1)
        self.assertEqual(api.active, BASE)
        self.assertEqual(self.report()["reason"], "replacement_expired")

    def test_no_watermark_requires_explicit_matching_unwatermarked_qa(self):
        self.plan["watermarkEnabled"] = False
        self.save_inputs()
        self.assertEqual(self.run_rotation()[0], 1)
        self.qa["watermark_enabled"] = False
        del self.qa["checks"]["recipient_raster_on_every_page"]
        self.save_inputs()
        self.assertEqual(self.run_rotation()[0], 0)


if __name__ == "__main__":
    unittest.main()
