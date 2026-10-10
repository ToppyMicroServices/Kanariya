"""Synthetic source-release tests; no credentials or provider requests."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

SPEC = importlib.util.spec_from_file_location("vault_release", Path(__file__).resolve().parents[1] / "scripts/deploy_vault_source.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
BASE = "11111111-1111-4111-8111-111111111111"
NEW = "22222222-2222-4222-8222-222222222222"
OLD_BODY, NEW_BODY = b"export default {fetch(){return new Response('old')}}", b"export default {fetch(){return new Response('new')}}"
RECIPIENT = "synthetic-recipient@example.test"
SENDER = "synthetic-sender@example.test"
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
            row["text"] = SECRET_MARKER  # Unexpected provider fields must not enter evidence.
    return rows


class FakeAPI:
    def __init__(self, failure=None):
        self.active, self.latest = BASE, BASE
        self.calls, self.posts = [], []
        self.failure = failure
        self.settings_reads = 0
        self.runtime = {"migration_tag": "v1-vault", "compatibility_date": "2026-01-12",
                        "compatibility_flags": ["nodejs_compat"], "usage_model": "standard",
                        "limits": {"cpu_ms": 30000}}

    def __call__(self, path, method="GET", data=None, content_type=None, raw=False):
        self.calls.append((method, path))
        if method == "POST":
            self.posts.append((path, data))
            if path == release.SCRIPT + "/versions":
                if self.failure == "upload_timeout":
                    raise release.SafeFailure("api_transport_unknown")
                self.latest = NEW
                return {"id": NEW}
            if path == release.SCRIPT + "/deployments":
                self.active = NEW
                if self.failure == "activation_timeout":
                    raise release.SafeFailure("api_transport_unknown")
                return {"id": "synthetic-deployment"}
            raise AssertionError("unexpected mutation")
        if path == release.SCRIPT + "/deployments":
            return {"deployments": [{"versions": [{"version_id": self.active, "percentage": 100}]}]}
        if path == release.SCRIPT + "/versions":
            return {"items": [{"id": self.latest}]}
        if path.startswith(release.SCRIPT + "/versions/"):
            return {"id": path.rsplit("/", 1)[1], "resources": {"bindings": bindings(),
                    "script_runtime": copy.deepcopy(self.runtime),
                    "script": {"handlers": ["fetch"], "named_handlers": ["VaultDocument"]}}}
        if path == release.SCRIPT + "/settings":
            self.settings_reads += 1
            value = {"bindings": bindings(), "compatibility_date": "2026-01-12",
                     "compatibility_flags": ["nodejs_compat"], "observability": {"enabled": False}}
            if (self.failure == "preupload_drift" and self.settings_reads >= 2 or
                self.failure == "postactivation_drift" and self.active == NEW):
                value["observability"]["enabled"] = True
            return value
        if path == release.SCRIPT + "/content/v2":
            body = OLD_BODY if self.latest == BASE else NEW_BODY
            if self.failure == "wrong_uploaded_source" and self.latest == NEW:
                body = b"unexpected-source"
            encoded = (b'--synthetic\r\nContent-Disposition: form-data; name="worker.js"; filename="worker.js"\r\n'
                       b'Content-Type: application/javascript+module\r\n\r\n' + body + b"\r\n--synthetic--\r\n")
            return "multipart/form-data; boundary=synthetic", encoded
        if path == release.SCRIPT + "/subdomain":
            return {"enabled": False, "previews_enabled": False}
        if path == f"/accounts/{release.ACCOUNT}/workers/domains":
            return [{"service": release.WORKER, "hostname": "vault.toppymicros.com", "environment": "production"}]
        if path.startswith("/zones?"):
            return [{"id": release.ZONE, "account": {"id": release.ACCOUNT}}]
        if path == f"/zones/{release.ZONE}/workers/routes":
            return []
        bucket = f"/accounts/{release.ACCOUNT}/r2/buckets/{release.BUCKET}"
        if path.startswith(bucket):
            if self.failure == "r2_permission":
                error = release.SafeFailure("api_http_403")
                error.http_status, error.api_codes, error.api_resource = 403, [10000], "r2_public_metadata"
                raise error
            return {"name": release.BUCKET} if path == bucket else {"enabled": False} if path.endswith("/managed") else {"domains": []}
        raise AssertionError("unexpected read: " + path)


class SourceReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        self.bundle = self.directory / "worker.js"
        self.tests = self.directory / "runtime.json"
        self.report = self.directory / "deployment.json"
        self.bundle.write_bytes(NEW_BODY)
        self.valid_tests = {"status": "passed", "pass": True, "candidateSha256": release.digest(NEW_BODY),
            "candidateSha256After": release.digest(NEW_BODY), "realDataUsed": False, "liveNotificationsSent": False,
            "compatibilityDate": "2026-01-12", "compatibilityFlags": ["nodejs_compat"]}
        self.tests.write_text(json.dumps(self.valid_tests))
        self.recipient_patch = patch.object(release, "RECIPIENT_SHA256", release.digest(RECIPIENT.encode()))
        self.recipient_patch.start()
        self.addCleanup(self.recipient_patch.stop)
        self.sender_patch = patch.object(release, "SENDER_SHA256", release.digest(SENDER.encode()))
        self.sender_patch.start()
        self.addCleanup(self.sender_patch.stop)

    def run_release(self, api):
        output = io.StringIO()
        with patch.object(release, "API", return_value=api) as constructor, patch("sys.stdout", output):
            status = release.main(["--bundle", str(self.bundle), "--sha256", release.digest(NEW_BODY),
                                   "--tests", str(self.tests), "--report", str(self.report)])
        return status, constructor, output.getvalue()

    def test_uploads_and_activates_only_exact_source_with_inherited_configuration(self):
        api = FakeAPI()
        status, _, output = self.run_release(api)
        self.assertEqual(status, 0)
        report = json.loads(self.report.read_text())
        self.assertEqual(report["phase"], "active_source_and_configuration_verified")
        self.assertEqual(report["remoteMutations"], 2)
        self.assertEqual(self.report.stat().st_mode & 0o777, 0o600)
        self.assertEqual([path for path, _ in api.posts], [release.SCRIPT + "/versions", release.SCRIPT + "/deployments"])
        multipart = api.posts[0][1]
        self.assertIn(b'filename="worker.js"', multipart)
        self.assertIn(NEW_BODY, multipart)
        for forbidden in (b'"bindings"', b'"vars"', b'"migrations"', b'"migration_tag"', SECRET_MARKER.encode(), RECIPIENT.encode()):
            self.assertNotIn(forbidden, multipart)
        self.assertIn(b'"keep_bindings"', multipart)
        self.assertIn(b'"limits": {"cpu_ms": 30000}', multipart)
        self.assertEqual(api.posts[1][1]["versions"], [{"version_id": NEW, "percentage": 100}])
        for marker in (SECRET_MARKER, RECIPIENT, SENDER):
            self.assertNotIn(marker, output + self.report.read_text())

    def test_unapproved_notification_sender_stops_before_upload(self):
        api = FakeAPI()
        rows = bindings()
        next(row for row in rows if row["name"] == "NOTIFY_EMAIL")["allowed_sender_addresses"] = ["unapproved@example.test"]
        with patch(__name__ + ".bindings", return_value=rows):
            self.assertEqual(self.run_release(api)[0], 1)
        self.assertEqual(api.posts, [])

    def test_missing_r2_permission_stops_before_any_mutation_and_reports_safe_codes(self):
        api = FakeAPI("r2_permission")
        status, _, output = self.run_release(api)
        self.assertEqual(status, 1)
        self.assertEqual(api.posts, [])
        report = json.loads(self.report.read_text())
        self.assertEqual(report["remoteMutations"], 0)
        self.assertEqual(report["phase"], "read_only_preflight")
        self.assertEqual((report["httpStatus"], report["apiErrorCodes"], report["apiResource"]), (403, [10000], "r2_public_metadata"))
        self.assertIn('"apiErrorCodes": [10000]', output)

    def test_preupload_configuration_drift_stops_without_mutation(self):
        api = FakeAPI("preupload_drift")
        self.assertEqual(self.run_release(api)[0], 1)
        self.assertEqual(api.posts, [])

    def test_active_must_be_latest_before_inheritance(self):
        api = FakeAPI()
        api.latest = NEW
        self.assertEqual(self.run_release(api)[0], 1)
        self.assertEqual(api.posts, [])

    def test_upload_uncertainty_never_retries_or_activates(self):
        api = FakeAPI("upload_timeout")
        self.assertEqual(self.run_release(api)[0], 1)
        self.assertEqual(len(api.posts), 1)
        report = json.loads(self.report.read_text())
        self.assertEqual(report["phase"], "upload_attempt_started")
        self.assertIsNone(report["remoteMutations"])

    def test_uploaded_source_readback_mismatch_never_activates(self):
        api = FakeAPI("wrong_uploaded_source")
        self.assertEqual(self.run_release(api)[0], 1)
        self.assertEqual(len(api.posts), 1)
        self.assertEqual(api.active, BASE)
        self.assertEqual(json.loads(self.report.read_text())["phase"], "uploaded_not_active")

    def test_activation_uncertainty_never_retries_or_rolls_back(self):
        api = FakeAPI("activation_timeout")
        self.assertEqual(self.run_release(api)[0], 1)
        self.assertEqual(len(api.posts), 2)
        report = json.loads(self.report.read_text())
        self.assertEqual(report["phase"], "activation_attempt_started")
        self.assertIsNone(report["remoteMutations"])

    def test_postactivation_drift_is_reported_as_unverified_without_rollback(self):
        api = FakeAPI("postactivation_drift")
        self.assertEqual(self.run_release(api)[0], 1)
        self.assertEqual(len(api.posts), 2)
        self.assertEqual(api.active, NEW)
        report = json.loads(self.report.read_text())
        self.assertEqual(report["phase"], "activation_acknowledged")
        self.assertEqual(report["status"], "stopped_preserve_state")

    def test_all_exact_runtime_requirements_are_checked_before_authentication(self):
        changes = {"status": "failed", "pass": False, "candidateSha256": "0" * 64,
                   "candidateSha256After": "0" * 64, "realDataUsed": True, "liveNotificationsSent": True,
                   "compatibilityDate": "2025-01-01", "compatibilityFlags": []}
        for key, value in changes.items():
            with self.subTest(key=key):
                self.tests.write_text(json.dumps({**self.valid_tests, key: value}))
                status, constructor, _ = self.run_release(FakeAPI())
                self.assertEqual(status, 1)
                constructor.assert_not_called()
                self.assertFalse(self.report.exists())

    def test_existing_report_and_symlink_inputs_are_preserved_before_authentication(self):
        self.report.write_text("existing-evidence")
        status, constructor, _ = self.run_release(FakeAPI())
        self.assertEqual(status, 1)
        constructor.assert_not_called()
        self.assertEqual(self.report.read_text(), "existing-evidence")
        self.report.unlink()
        self.bundle.unlink()
        self.bundle.symlink_to(self.tests)
        status, constructor, _ = self.run_release(FakeAPI())
        self.assertEqual(status, 1)
        constructor.assert_not_called()

    def test_http_error_reports_only_status_and_integer_codes(self):
        payload = json.dumps({"success": False, "errors": [{"code": 10000, "message": SECRET_MARKER},
            {"code": SECRET_MARKER, "message": RECIPIENT}]}).encode()
        with patch.dict("os.environ", {"CLOUDFLARE_API_TOKEN": SECRET_MARKER, "CLOUDFLARE_ACCOUNT_ID": release.ACCOUNT}):
            api = release.API()
        error = urllib.error.HTTPError("https://api.cloudflare.com", 403, SECRET_MARKER, {}, io.BytesIO(payload))
        with patch.object(api.opener, "open", side_effect=error):
            with self.assertRaises(release.SafeFailure) as caught:
                api(f"/accounts/{release.ACCOUNT}/r2/buckets/{release.BUCKET}")
        self.assertEqual(str(caught.exception), "api_http_403")
        self.assertEqual(caught.exception.api_codes, [10000])
        self.assertEqual(caught.exception.api_resource, "r2_public_metadata")


if __name__ == "__main__":
    unittest.main()
