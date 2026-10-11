"""Synthetic local evidence and mocked activation; no private files or provider calls."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "vault_document_rotation", Path(__file__).resolve().parents[1] / "scripts/rotate_vault_document.py")
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)
FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "vault_dummy_rotation_fixtures", Path(__file__).with_name("rotate_vault_dummy_test.py"))
fixtures = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(fixtures)
release = helper.release
NOW, PDF, SOURCE = fixtures.NOW, fixtures.PDF, fixtures.SOURCE


class DocumentRotationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.manifest_path = self.directory / "manifest.json"
        self.pdf_path = self.directory / "final.pdf"
        self.qa_path = self.directory / "qa-report.json"
        self.visual_path = self.directory / "visual-review.json"
        self.owner_path = self.directory / "owner-approval.json"
        self.report_path = self.directory / "operation.json"
        self.recipient = {"type": "organization", "organizationName": "Synthetic Organization", "personName": "Synthetic Reviewer"}
        self.manifest = {"version": 2, "status": "prepared_not_active", "id": fixtures.CANDIDATE,
                         "currentDocumentId": release.FIXED_VARS["DUMMY_DOCUMENT_ID"],
                         "currentRecordSha256": release.FIXED_VARS["DUMMY_RECORD_SHA256"],
                         "recordSha256": release.digest(b"synthetic encrypted final document"),
                         "preparedSha256": release.digest(PDF), "sourceSha256": release.digest(b"synthetic source PDF"),
                         "recipient": copy.deepcopy(self.recipient), "recipientName": "Synthetic Organization Synthetic Reviewer",
                         "watermarkEnabled": False, "expiresAt": NOW + 86400000, "authMode": "link",
                         "registryRevision": 2, "createdAt": NOW - 1000}
        self.pdf_path.write_bytes(PDF)
        images = []
        for engine in helper.ENGINES:
            for page in (1, 2):
                target = self.directory / f"renders/{engine}/page-{page}.png"
                target.parent.mkdir(parents=True, exist_ok=True)
                body = f"synthetic mocked {engine} page {page}".encode()
                target.write_bytes(body)
                images.append({"engine": engine, "page": page, "path": str(target), "sha256": release.digest(body)})
        checks = {name: {"status": "pass"} for name in helper.REQUIRED_CHECKS}
        checks["final_qpdf"]["output"] = "No syntax or stream encoding errors found; the file may still contain errors that qpdf cannot detect"
        checks["final_ghostscript"]["output"] = "none"
        for name in ("final_qpdf", "final_ghostscript"):
            checks[name]["exit_code"] = 0
        checks["final_poppler_structure"]["output"] = "no warnings"
        for engine in helper.ENGINES:
            checks[engine + "_render"].update(pages=2, output="none")
        checks["pdfjs_render"]["cMapUrl"] = "omitted"
        preview = self.directory / "preview.png"
        preview.write_bytes(b"synthetic preview")
        self.qa = {"status": "automated_pass", "final_pdf": {"path": str(self.pdf_path), "sha256": release.digest(PDF),
                    "pages": 2, "size_bytes": len(PDF)}, "checks": checks,
                   "tool_versions": {name: "synthetic mocked version" for name in (*helper.ENGINES, "qpdf", "ghostscript")},
                   "qa_artifacts": {"images": images, "preview": str(preview), "preview_sha256": release.digest(preview.read_bytes())}}
        self.visual = {"status": "assistant_visual_review_passed", "pdf_sha256": release.digest(PDF),
                       "qa_report_sha256": "", "images": copy.deepcopy(images)}
        self.owner = {"version": 1, "status": "approved_exact_document_activation", "scope": helper.SCOPE,
                      "approvedAt": NOW, "manifestSha256": "", "finalPdfSha256": release.digest(PDF),
                      "qaReportSha256": "", "visualReviewSha256": "", "recipient": copy.deepcopy(self.recipient),
                      "recipientName": self.manifest["recipientName"], "expiresAt": self.manifest["expiresAt"],
                      "origin": release.FIXED_VARS["PUBLIC_ORIGIN"], "bucket": release.BUCKET,
                      "adminPath": "/v1/admin", "gateExitCode": 0, "broadPublicationApproved": False}
        self.save_inputs()
        for target, name, value in ((release, "RECIPIENT_SHA256", release.digest(fixtures.RECIPIENT.encode())),
                                    (release, "SENDER_SHA256", release.digest(fixtures.SENDER.encode())),
                                    (helper, "now_ms", lambda: NOW), (helper.rotation, "now_ms", lambda: NOW)):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def save_inputs(self):
        self.manifest_path.write_text(json.dumps(self.manifest, indent=2) + "\n")
        self.qa_path.write_text(json.dumps(self.qa))
        self.visual["qa_report_sha256"] = release.digest(self.qa_path.read_bytes())
        self.visual_path.write_text(json.dumps(self.visual))
        self.owner.update(manifestSha256=release.digest(self.manifest_path.read_bytes()),
                          qaReportSha256=release.digest(self.qa_path.read_bytes()),
                          visualReviewSha256=release.digest(self.visual_path.read_bytes()))
        self.owner_path.write_text(json.dumps(self.owner))

    def run_helper(self, api=None, execute=False, approve=None, owner=True):
        api = api or fixtures.FakeAPI()
        output = io.StringIO()
        args = ["--manifest", str(self.manifest_path), "--pdf", str(self.pdf_path),
                "--qa-report", str(self.qa_path), "--visual-review", str(self.visual_path), "--report", str(self.report_path)]
        if owner:
            args.extend(["--owner-approval", str(self.owner_path)])
        if execute:
            args.append("--execute")
        if approve is not None:
            args.extend(["--approve", approve])
        with patch.object(helper, "API", return_value=api) as constructor, patch("sys.stdout", output):
            status = helper.main(args)
        return status, api, constructor, output.getvalue()

    def approved(self, api=None):
        return self.run_helper(api, execute=True, approve=release.digest(self.manifest_path.read_bytes()))

    def report(self):
        return json.loads(self.report_path.read_text())

    def assert_local_rejection(self, execute=False, owner=True):
        status, api, constructor, output = self.run_helper(execute=execute, owner=owner)
        self.assertEqual(status, 1)
        self.assertEqual(api.calls, [])
        constructor.assert_not_called()
        self.assertNotIn(self.manifest.get("recipientName", self.owner["recipientName"]), output)
        self.assertNotIn(fixtures.SECRET_MARKER, output)
        return output

    def test_default_preflight_only_reads_worker_metadata_and_reports_separate_r2_gap(self):
        status, api, _, output = self.run_helper()
        self.assertEqual(status, 0)
        self.assertEqual(api.posts, [])
        report = self.report()
        self.assertEqual(report["status"], "reviewed_not_executed")
        self.assertEqual(report["remoteMutations"], 0)
        self.assertTrue(report["ownerApprovalRecordMatched"])
        self.assertTrue(report["assistantVisualReviewRecordMatched"])
        self.assertFalse(report["r2PublicConfigurationVerified"])
        self.assertFalse(report["privateReplacementObjectVerified"])
        self.assertEqual(report["r2ApiRequests"], 0)
        self.assertFalse(any("/r2/" in path for _, path in api.calls))
        self.assertNotIn(self.manifest["recipientName"], output)
        self.assertEqual(self.report_path.stat().st_mode & 0o777, 0o600)

    def test_execution_preserves_source_keys_and_every_other_binding_and_fixed_baseline(self):
        fixed = copy.deepcopy(release.FIXED_VARS)
        status, api, _, output = self.approved()
        self.assertEqual(status, 0)
        self.assertEqual(api.active, fixtures.NEW)
        self.assertEqual(api.uploaded_source, SOURCE)
        self.assertEqual(len(api.posts), 2)
        self.assertEqual(release.FIXED_VARS, fixed)
        old = {row["name"]: row for row in api.rows[fixtures.BASE]}
        new = {row["name"]: row for row in api.rows[fixtures.NEW]}
        for name in old.keys() - helper.rotation.PIN_NAMES:
            # Provider secret values are never requested, retained or rewritten.
            self.assertEqual(old[name], new[name])
        self.assertEqual(new["DUMMY_DOCUMENT_ID"]["text"], self.manifest["id"])
        self.assertEqual(new["DUMMY_RECORD_SHA256"]["text"], self.manifest["recordSha256"])
        self.assertEqual(api.metadata["keep_bindings"], ["durable_object_namespace", "r2_bucket", "secret_text", "send_email"])
        self.assertNotIn(fixtures.SECRET_MARKER, self.report_path.read_text())
        self.assertNotIn(fixtures.SECRET_MARKER.encode(), api.posts[0][1])
        self.assertNotIn(self.manifest["recipientName"], output)
        self.assertTrue(self.report()["exactDocumentPinsVerified"])

    def test_current_dummy_helper_and_global_guards_are_not_replaced(self):
        dummy = Path(helper.rotation.__file__)
        before = dummy.read_bytes()
        plan_fields = helper.rotation.PLAN_FIELDS.copy()
        self.assertEqual(self.approved()[0], 0)
        self.assertEqual(dummy.read_bytes(), before)
        self.assertEqual(helper.rotation.PLAN_FIELDS, plan_fields)

    def test_execution_requires_both_manifest_hash_and_separate_owner_receipt(self):
        self.assert_local_rejection(execute=True)
        self.assert_local_rejection(owner=False)
        self.owner_path.unlink()
        self.assert_local_rejection()

    def test_mismatching_execute_hash_and_wrong_record_hash_are_rejected(self):
        status, api, constructor, _ = self.run_helper(execute=True, approve="f" * 64)
        self.assertEqual(status, 1)
        constructor.assert_not_called()
        self.assertEqual(api.calls, [])
        self.owner["manifestSha256"] = "f" * 64
        self.owner_path.write_text(json.dumps(self.owner))
        self.assert_local_rejection()

    def test_old_password_mode_and_neutral_dummy_manifests_are_rejected(self):
        for changes in ({"version": 1}, {"authMode": "password"}, {"authMode": "access"}):
            with self.subTest(changes=changes):
                original = copy.deepcopy(self.manifest)
                self.manifest.update(changes)
                self.save_inputs()
                self.assert_local_rejection()
                self.manifest = original
        del self.manifest["recipient"]
        del self.manifest["recipientName"]
        self.save_inputs()
        self.assert_local_rejection()

    def test_extra_private_or_password_fields_are_rejected_without_echo(self):
        for name in ("password", "passwordVerifier", "subjects", "applicantName"):
            with self.subTest(name=name):
                self.manifest[name] = fixtures.SECRET_MARKER
                self.save_inputs()
                self.assert_local_rejection()
                del self.manifest[name]

    def test_manifest_requires_exact_current_dummy_baseline_and_policy(self):
        for field, value in (("currentDocumentId", fixtures.DRIFT), ("currentRecordSha256", "f" * 64),
                             ("id", self.manifest["currentDocumentId"]), ("registryRevision", True),
                             ("createdAt", NOW + 1), ("expiresAt", NOW), ("watermarkEnabled", 1),
                             ("recordSha256", "BAD")):
            with self.subTest(field=field):
                original = self.manifest[field]
                self.manifest[field] = value
                self.save_inputs()
                self.assert_local_rejection()
                self.manifest[field] = original

    def test_recipient_schema_normalization_and_join_are_exact(self):
        invalid = [dict(self.recipient, extra="private"), dict(self.recipient, type="other"),
                   dict(self.recipient, organizationName=""), dict(self.recipient, organizationName=" padded "),
                   dict(self.recipient, organizationName="Cafe\u0301"), dict(self.recipient, personName="../other"),
                   dict(self.recipient, organizationName="\ufeffSynthetic Org"),
                   dict(self.recipient, personName="x\nname"), dict(self.recipient, personName="x" * 181),
                   {"type": "person", "organizationName": "not-null", "personName": "Synthetic Person"}]
        for recipient in invalid:
            with self.subTest(recipient=recipient):
                self.manifest["recipient"] = recipient
                self.save_inputs()
                self.assert_local_rejection()
        self.manifest["recipient"] = copy.deepcopy(self.recipient)
        self.manifest["recipientName"] = "Other Person"
        self.save_inputs()
        self.assert_local_rejection()

    def test_person_recipient_and_organization_without_person_are_supported(self):
        for recipient, name in (({"type": "person", "organizationName": None, "personName": "Synthetic Person"}, "Synthetic Person"),
                                ({"type": "organization", "organizationName": "Synthetic Org", "personName": None}, "Synthetic Org")):
            self.manifest.update(recipient=recipient, recipientName=name)
            self.owner.update(recipient=recipient, recipientName=name)
            self.save_inputs()
            self.assertEqual(self.run_helper()[0], 0)
            self.report_path.unlink()

    def test_malformed_duplicate_and_nonfinite_json_are_rejected_for_every_record(self):
        for path in (self.manifest_path, self.qa_path, self.visual_path, self.owner_path):
            original = path.read_bytes()
            for body in (b"{bad", b'{"version":1,"version":2}', b'{"value":NaN}', b"[]"):
                with self.subTest(path=path.name, body=body):
                    path.write_bytes(body)
                    self.assert_local_rejection()
            path.write_bytes(original)

    def test_duplicate_nested_owner_recipient_fields_are_rejected(self):
        body = self.owner_path.read_text().replace('"type": "organization"', '"type": "organization", "type": "person"')
        self.owner_path.write_text(body)
        self.assert_local_rejection()

    def test_every_artifact_symlink_is_rejected(self):
        paths = [self.manifest_path, self.pdf_path, self.qa_path, self.visual_path, self.owner_path,
                 Path(self.qa["qa_artifacts"]["images"][0]["path"]), Path(self.qa["qa_artifacts"]["preview"])]
        for path in paths:
            with self.subTest(path=path.name):
                target = path.with_name(path.name + ".target")
                path.rename(target)
                path.symlink_to(target)
                self.assert_local_rejection()
                path.unlink()
                target.rename(path)

    def test_symlinked_artifact_parent_and_existing_report_are_rejected(self):
        linked = self.directory / "linked"
        linked.symlink_to(self.directory, target_is_directory=True)
        self.pdf_path = linked / "final.pdf"
        self.assert_local_rejection()
        self.pdf_path = self.directory / "final.pdf"
        self.report_path.write_text("unrelated local work")
        self.assert_local_rejection()
        self.assertEqual(self.report_path.read_text(), "unrelated local work")

    def test_qa_pdf_hash_size_path_or_failed_check_stops_before_remote_reads(self):
        for field, value in (("sha256", "f" * 64), ("path", str(self.directory / "other.pdf")),
                             ("size_bytes", len(PDF) + 1), ("pages", True), ("pages", 21)):
            with self.subTest(field=field):
                original = self.qa["final_pdf"][field]
                self.qa["final_pdf"][field] = value
                self.save_inputs()
                self.assert_local_rejection()
                self.qa["final_pdf"][field] = original
        self.qa["checks"]["fonts"]["status"] = "failed"
        self.save_inputs()
        self.assert_local_rejection()

    def test_changed_final_pdf_or_missing_mandatory_qa_check_stops(self):
        self.pdf_path.write_bytes(PDF + b"changed")
        self.assert_local_rejection()
        self.pdf_path.write_bytes(PDF)
        del self.qa["checks"]["final_qpdf"]
        self.save_inputs()
        self.assert_local_rejection()

    def test_pdf_over_runtime_size_limit_is_rejected_before_provider_preflight(self):
        oversized = b"%PDF-1.7\n" + b"x" * helper.MAX_PDF
        self.pdf_path.write_bytes(oversized)
        self.manifest["preparedSha256"] = release.digest(oversized)
        self.qa["final_pdf"].update(sha256=release.digest(oversized), size_bytes=len(oversized))
        self.visual["pdf_sha256"] = release.digest(oversized)
        self.owner["finalPdfSha256"] = release.digest(oversized)
        self.save_inputs()
        self.assert_local_rejection()

    def test_structural_and_cmap_warning_output_cannot_be_marked_passed(self):
        for name, value in (("final_qpdf", "WARNING: incorrect xref"), ("final_ghostscript", "repaired recursive dict"),
                            ("final_poppler_structure", "Syntax Error: malformed PDF"),
                            ("pdfjs_render", "Unable to load CMap"), ("quartz_render", "warning")):
            with self.subTest(name=name):
                original = self.qa["checks"][name]["output"]
                self.qa["checks"][name]["output"] = value
                self.save_inputs()
                self.assert_local_rejection()
                self.qa["checks"][name]["output"] = original

    def test_explicit_nonzero_qa_exit_code_or_warning_list_stops(self):
        original = copy.deepcopy(self.qa["checks"]["final_qpdf"])
        for field, value in (("exit_code", 1), ("exit_code", False), ("warnings", ["warning"]),
                             ("structural_warnings", ["incorrect xref"])):
            self.qa["checks"]["final_qpdf"] = copy.deepcopy(original)
            self.qa["checks"]["final_qpdf"][field] = value
            self.save_inputs()
            self.assert_local_rejection()

    def test_structural_checks_require_explicit_integer_zero_exit_codes(self):
        for name in ("final_qpdf", "final_ghostscript"):
            original = copy.deepcopy(self.qa["checks"][name])
            for missing, value in ((True, None), (False, None), (False, False), (False, 0.0),
                                   (False, "0"), (False, 1), (False, -1)):
                with self.subTest(check=name, missing=missing, value=value):
                    self.qa["checks"][name] = copy.deepcopy(original)
                    if missing:
                        del self.qa["checks"][name]["exit_code"]
                    else:
                        self.qa["checks"][name]["exit_code"] = value
                    self.save_inputs()
                    output = self.assert_local_rejection(execute=True)
                    self.assertEqual(json.loads(output)["reason"], "qa_exit_code_must_be_zero")
            self.qa["checks"][name] = original

    def test_each_renderer_and_structural_tool_requires_a_nonblank_string_version(self):
        original = copy.deepcopy(self.qa["tool_versions"])
        for engine in (*helper.ENGINES, "qpdf", "ghostscript"):
            for missing, value in ((True, None), (False, None), (False, ""), (False, " \t\n"),
                                   (False, False), (False, 1), (False, {"version": "1"})):
                with self.subTest(engine=engine, missing=missing, value=value):
                    self.qa["tool_versions"] = copy.deepcopy(original)
                    if missing:
                        del self.qa["tool_versions"][engine]
                    else:
                        self.qa["tool_versions"][engine] = value
                    self.save_inputs()
                    output = self.assert_local_rejection(execute=True)
                    self.assertEqual(json.loads(output)["reason"], "renderer_versions_required")
        self.qa["tool_versions"] = {"unrelated": "1"}
        self.save_inputs()
        output = self.assert_local_rejection(execute=True)
        self.assertEqual(json.loads(output)["reason"], "renderer_versions_required")

    def test_quartz_os_version_alias_is_supported(self):
        del self.qa["tool_versions"]["quartz"]
        self.qa["tool_versions"]["macos_quartz_os"] = "synthetic macOS Quartz version"
        self.save_inputs()
        self.assertEqual(self.run_helper()[0], 0)
        self.report_path.unlink()
        self.qa["tool_versions"]["quartz"] = ""
        self.save_inputs()
        self.assertEqual(self.run_helper()[0], 0)

    def test_blank_quartz_os_alias_cannot_replace_missing_quartz_version(self):
        del self.qa["tool_versions"]["quartz"]
        self.qa["tool_versions"]["macos_quartz_os"] = " \t\n"
        self.save_inputs()
        output = self.assert_local_rejection(execute=True)
        self.assertEqual(json.loads(output)["reason"], "renderer_versions_required")

    def test_all_four_engines_every_page_unique_path_and_page_are_required(self):
        images = self.qa["qa_artifacts"]["images"]
        for changes in ({"engine": "pdfkit"}, {"page": 0}, {"page": True}, {"page": 2},
                        {"path": images[1]["path"]}, {"sha256": "f" * 64}):
            with self.subTest(changes=changes):
                original = copy.deepcopy(images[0])
                images[0].update(changes)
                self.save_inputs()
                self.assert_local_rejection()
                images[0] = original
        images.pop()
        self.save_inputs()
        self.assert_local_rejection()

    def test_image_escape_or_changed_image_and_preview_bytes_stop(self):
        images = self.qa["qa_artifacts"]["images"]
        original = images[0]["path"]
        for value in ("../escape.png", "/private/tmp/outside-final-qa.png"):
            images[0]["path"] = value
            self.save_inputs()
            self.assert_local_rejection()
        images[0]["path"] = original
        self.save_inputs()
        Path(original).write_bytes(b"changed synthetic image")
        self.assert_local_rejection()
        Path(original).write_bytes(b"synthetic mocked quartz page 1")
        Path(self.qa["qa_artifacts"]["preview"]).write_bytes(b"changed preview")
        self.assert_local_rejection()

    def test_visual_record_must_match_exact_pdf_qa_and_page_images(self):
        for field, value in (("status", "user_confirmed"), ("pdf_sha256", "f" * 64)):
            original = self.visual[field]
            self.visual[field] = value
            self.save_inputs()
            self.assert_local_rejection()
            self.visual[field] = original
        self.save_inputs()
        self.visual["qa_report_sha256"] = "f" * 64
        self.visual_path.write_text(json.dumps(self.visual))
        self.assert_local_rejection()
        self.save_inputs()
        self.visual["images"][0]["sha256"] = "f" * 64
        self.save_inputs()
        self.assert_local_rejection()

    def test_owner_receipt_rejects_wrong_scope_origin_bucket_admin_or_broad_publication(self):
        for field, value in (("scope", "publish"), ("origin", "https://other.example.test"), ("bucket", "other-bucket"),
                             ("adminPath", "/admin/"), ("broadPublicationApproved", True), ("version", True),
                             ("status", "prepared"), ("gateExitCode", 1), ("approvedAt", NOW + 1)):
            original = self.owner[field]
            self.owner[field] = value
            self.save_inputs()
            self.assert_local_rejection()
            self.owner[field] = original
        self.owner["secret"] = fixtures.SECRET_MARKER
        self.save_inputs()
        self.assert_local_rejection()

    def test_owner_receipt_requires_exact_recipient_expiry_and_all_hashes(self):
        for field, value in (("recipientName", "Another recipient"), ("recipient", dict(self.recipient, personName="Another person")),
                             ("expiresAt", NOW + 1), ("finalPdfSha256", "f" * 64), ("manifestSha256", "f" * 64),
                             ("qaReportSha256", "f" * 64), ("visualReviewSha256", "f" * 64)):
            original = self.owner[field]
            self.owner[field] = value
            self.owner_path.write_text(json.dumps(self.owner))
            self.assert_local_rejection()
            self.owner[field] = original

    def test_preflight_configuration_or_permission_drift_prevents_upload(self):
        for failure in ("permission", "split", "latest_not_active", "preupload_drift", "public_endpoint", "route"):
            with self.subTest(failure=failure):
                if self.report_path.exists():
                    self.report_path.unlink()
                status, api, _, _ = self.approved(fixtures.FakeAPI(failure))
                self.assertEqual(status, 1)
                self.assertEqual(api.posts, [])

    def test_binding_source_runtime_or_export_drift_prevents_activation(self):
        for failure in ("wrong_new_pin", "missing_secret_binding", "canary_binding_added", "changed_do_namespace",
                        "new_runtime", "new_handlers", "new_version_source", "wrong_source", "afterupload_settings_other_pin",
                        "preactivation_drift"):
            with self.subTest(failure=failure):
                if self.report_path.exists():
                    self.report_path.unlink()
                status, api, _, _ = self.approved(fixtures.FakeAPI(failure))
                self.assertEqual(status, 1)
                self.assertEqual(len(api.posts), 1)
                self.assertEqual(api.active, fixtures.BASE)

    def test_uncertain_upload_never_retries_or_activates(self):
        status, api, _, _ = self.approved(fixtures.FakeAPI("upload_timeout"))
        self.assertEqual(status, 1)
        self.assertEqual(len(api.posts), 1)
        self.assertIsNone(self.report()["remoteMutations"])
        self.assertEqual(self.report()["phase"], "upload_attempt_started")

    def test_uncertain_activation_never_retries_or_rolls_back(self):
        status, api, _, _ = self.approved(fixtures.FakeAPI("activation_timeout"))
        self.assertEqual(status, 1)
        self.assertEqual(len(api.posts), 2)
        self.assertIsNone(self.report()["remoteMutations"])
        self.assertEqual(self.report()["phase"], "activation_attempt_started")
        self.assertFalse(self.report()["exactDocumentPinsVerified"])

    def test_failed_final_readback_does_not_claim_verified_activation(self):
        status, api, _, _ = self.approved(fixtures.FakeAPI("postactivation_drift"))
        self.assertEqual(status, 1)
        self.assertEqual(len(api.posts), 2)
        self.assertNotEqual(self.report()["status"], "passed")
        self.assertFalse(self.report()["exactDocumentPinsVerified"])

    def test_local_artifacts_rechecked_before_upload_and_activation(self):
        class ChangeAfterPreflight(fixtures.FakeAPI):
            def __call__(api, path, method="GET", **kwargs):
                result = super(ChangeAfterPreflight, api).__call__(path, method=method, **kwargs)
                if path == release.SCRIPT + "/settings" and api.settings_reads == 2:
                    self.pdf_path.write_bytes(PDF + b"changed after local gate")
                return result

        status, api, _, _ = self.approved(ChangeAfterPreflight())
        self.assertEqual(status, 1)
        self.assertEqual(api.posts, [])
        self.assertEqual(self.report()["remoteMutations"], 0)
        self.pdf_path.write_bytes(PDF)
        self.report_path.unlink()

        class ChangeAfterUpload(fixtures.FakeAPI):
            def __call__(api, path, method="GET", **kwargs):
                result = super(ChangeAfterUpload, api).__call__(path, method=method, **kwargs)
                if path == release.SCRIPT + "/versions" and method == "POST":
                    self.owner_path.write_text("{}")
                return result

        status, api, _, _ = self.approved(ChangeAfterUpload())
        self.assertEqual(status, 1)
        self.assertEqual(len(api.posts), 1)
        self.assertEqual(api.active, fixtures.BASE)
        self.assertEqual(self.report()["remoteMutations"], 1)


if __name__ == "__main__":
    unittest.main()
