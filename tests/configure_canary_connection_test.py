"""Synthetic connection provisioning tests; no credentials or provider calls."""
import base64
import copy
import email.policy
from email.parser import BytesParser
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("canary_connection", Path(__file__).resolve().parents[1] /
                                           "scripts/configure_canary_connection.py")
connection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(connection)
release = connection.release
VAULT_BASE = "11111111-1111-4111-8111-111111111111"
VAULT_NEW = "22222222-2222-4222-8222-222222222222"
ROOT_BASE = "33333333-3333-4333-8333-333333333333"
ROOT_NEW = "44444444-4444-4444-8444-444444444444"
VAULT_SOURCE = b"export default {fetch(){return new Response('existing vault')}}"
ROOT_SOURCE = b"export default {fetch(){return new Response('existing canary')}}"
SECRET_MARKER = "synthetic-secret-never-written-to-evidence"
RECIPIENT, SENDER = "synthetic-recipient@example.test", "synthetic-sender@example.test"
GENERATED = bytes(range(32))
GENERATED_TEXT = base64.b64encode(GENERATED).decode("ascii")


def vault_bindings():
    rows = [{"name": name, "type": kind} for name, kind in release.BINDING_TYPES.items()]
    by_name = {row["name"]: row for row in rows}
    for name, value in release.FIXED_VARS.items():
        by_name[name]["text"] = value
    by_name["VAULT_DOCUMENTS"]["bucket_name"] = release.BUCKET
    by_name["VAULT"].update(namespace_id=release.NAMESPACE, class_name="VaultDocument")
    by_name["NOTIFY_EMAIL"].update(destination_address=RECIPIENT, allowed_sender_addresses=[SENDER])
    for row in rows:
        if row["type"] == "secret_text":
            row["text"] = SECRET_MARKER
    return rows


def root_bindings():
    return [{"name": "ADMIN_KEY", "type": "secret_text", "text": SECRET_MARKER},
            {"name": "IP_HMAC_KEY", "type": "secret_text", "text": SECRET_MARKER},
            {"name": "KANARI_KV", "type": "kv_namespace", "namespace_id": "synthetic-kv"},
            {"name": "KANARI_STORE", "type": "durable_object_namespace", "namespace_id": "synthetic-store",
             "class_name": "KanariyaStore"},
            {"name": "EVENT_TTL_SECONDS", "type": "plain_text", "text": "2592000"}]


class FakeAPI:
    def __init__(self, binding=False, key=False, failure=None):
        self.failure = failure
        vault, root = vault_bindings(), root_bindings()
        if binding:
            vault.append(dict(release.CANARY_BINDING))
        if key:
            root.append({"name": connection.SOURCE_KEY, "type": "secret_text", "text": SECRET_MARKER})
        self.workers = {}
        for script, version, rows, body, tag, flags, named in (
            (release.SCRIPT, VAULT_BASE, vault, VAULT_SOURCE, "v1-vault", ["nodejs_compat"], ["VaultDocument"]),
            (connection.ROOT, ROOT_BASE, root, ROOT_SOURCE, "v1-kanariya-store", [], ["KanariyaStore", "CanaryManagement"])):
            self.workers[script] = {"active": version, "latest": version, "rows": {version: rows},
                "sources": {version: body}, "runtime": {"migration_tag": tag, "compatibility_date": "2026-01-12",
                    "compatibility_flags": flags, "usage_model": "standard", "limits": {"cpu_ms": 30000}},
                "named": [{"name": name, "handlers": []} for name in named],
                "settings": {"compatibility_date": "2026-01-12", "compatibility_flags": flags,
                    "observability": {"enabled": False}, "logpush": False, "tail_consumers": [],
                    "placement": {"mode": "smart"}}, "settingsReads": 0, "contentReads": 0}
        self.calls, self.mutations, self.upload = [], [], None
        self.secret_reads = 0

    def __call__(self, path, method="GET", data=None, content_type=None, raw=False):
        self.calls.append((method, path))
        if "/r2/" in path or "/access/" in path or ("/secrets/" in path):
            raise AssertionError("R2, Access and individual secret reads are forbidden")
        script = next((name for name in self.workers if path.startswith(name + "/")), None)
        if method != "GET":
            self.mutations.append((method, path, data))
            if method == "POST" and path == release.SCRIPT + "/versions":
                if self.failure == "upload_timeout":
                    raise connection.SafeFailure("api_transport_unknown")
                msg = BytesParser(policy=email.policy.default).parsebytes(
                    ("Content-Type: " + content_type + "\r\nMIME-Version: 1.0\r\n\r\n").encode() + data)
                parts = list(msg.iter_parts())
                metadata = json.loads(parts[0].get_payload(decode=True))
                body = parts[1].get_payload(decode=True)
                self.upload = {"metadata": metadata, "source": body}
                worker = self.workers[script]
                worker["rows"][VAULT_NEW] = [copy.deepcopy(row) for row in worker["rows"][VAULT_BASE]
                                             if row["type"] in metadata["keep_bindings"]]
                worker["rows"][VAULT_NEW].extend(copy.deepcopy(metadata["bindings"]))
                worker["sources"][VAULT_NEW] = b"changed" if self.failure == "uploaded_source" else body
                worker["latest"] = VAULT_NEW
                worker["settings"]["placement"] = copy.deepcopy(metadata.get("placement"))
                if self.failure == "uploaded_binding":
                    next(row for row in worker["rows"][VAULT_NEW] if row["name"] == "CANARY_ADMIN")["service"] = "other"
                return {"id": VAULT_NEW}
            if method == "POST" and path == release.SCRIPT + "/deployments":
                self.workers[script]["active"] = VAULT_NEW
                if self.failure == "activation_timeout":
                    raise connection.SafeFailure("api_transport_unknown")
                return {"id": "synthetic-deployment"}
            if method == "PUT" and path == connection.ROOT + "/secrets":
                worker = self.workers[script]
                self.assert_absent_source_key(worker)
                if self.failure == "key_put_timeout":
                    raise connection.SafeFailure("api_transport_unknown")
                worker["rows"][ROOT_NEW] = copy.deepcopy(worker["rows"][ROOT_BASE]) + [
                    {"name": data["name"], "type": data["type"]}]
                worker["sources"][ROOT_NEW] = ROOT_SOURCE
                worker["latest"] = ROOT_NEW
                if self.failure != "key_staged":
                    worker["active"] = ROOT_NEW
                if self.failure == "root_source_after_key":
                    worker["sources"][ROOT_NEW] = b"unexpected source"
                if self.failure == "root_settings_after_key":
                    worker["settings"]["observability"]["enabled"] = True
                return {"name": data["name"], "type": data["type"], "text": data["text"]}
            raise AssertionError("unapproved mutation")
        if script:
            worker = self.workers[script]
            suffix = path[len(script):]
            if suffix == "/deployments":
                return {"deployments": [{"versions": [{"version_id": worker["active"], "percentage":
                    50 if self.failure == "split" else 100}]}]}
            if suffix == "/versions":
                return {"items": [{"id": worker["latest"]}]}
            if suffix.startswith("/versions/"):
                version = suffix.rsplit("/", 1)[1]
                metadata = {"handlers": ["fetch"], "named_handlers": copy.deepcopy(worker["named"])}
                if self.failure != "no_etag":
                    metadata["etag"] = release.digest(worker["sources"][version])
                return {"id": version, "resources": {"bindings": copy.deepcopy(worker["rows"][version]),
                    "script_runtime": copy.deepcopy(worker["runtime"]), "script": metadata}}
            if suffix == "/settings":
                worker["settingsReads"] += 1
                if (self.failure == "preupload_drift" and script == release.SCRIPT and worker["settingsReads"] >= 3 or
                    self.failure == "preactivation_drift" and script == release.SCRIPT and worker["settingsReads"] >= 5):
                    worker["settings"]["observability"]["enabled"] = True
                return {**copy.deepcopy(worker["settings"]), "bindings": copy.deepcopy(worker["rows"][worker["latest"]])}
            if suffix == "/content/v2":
                worker["contentReads"] += 1
                body = worker["sources"][worker["latest"]]
                if self.failure == "root_preupload_source" and script == connection.ROOT and worker["contentReads"] >= 2:
                    body = b"changed root source"
                payload = (b'--synthetic\r\nContent-Disposition: form-data; name="worker.js"; filename="worker.js"\r\n'
                           b'Content-Type: application/javascript+module\r\n\r\n' + body + b'\r\n--synthetic--\r\n')
                return "multipart/form-data; boundary=synthetic", payload
            if suffix == "/subdomain":
                return {"enabled": script == connection.ROOT, "previews_enabled": False}
            if suffix == "/secrets" and script == connection.ROOT:
                self.secret_reads += 1
                if self.failure == "key_appeared" and self.secret_reads == 3:
                    worker["rows"][worker["latest"]].append({"name": connection.SOURCE_KEY, "type": "secret_text"})
                return [copy.deepcopy(row) for row in worker["rows"][worker["latest"]] if row["type"].startswith("secret_")]
            raise AssertionError("unexpected worker read")
        if path == f"/accounts/{release.ACCOUNT}/workers/domains":
            return [{"service": "kanariya-vault", "hostname": "vault.toppymicros.com", "environment": "production"}]
        if path.startswith("/zones?"):
            return [{"id": release.ZONE, "account": {"id": release.ACCOUNT}}]
        if path == f"/zones/{release.ZONE}/workers/routes":
            return [{"id": "synthetic-route", "pattern": "kanariya.toppymicros.com/canary/*", "script": "kanariya"}]
        raise AssertionError("unexpected read")

    @staticmethod
    def assert_absent_source_key(worker):
        if any(row["name"] == connection.SOURCE_KEY for row in worker["rows"][worker["latest"]]):
            raise AssertionError("existing source key must never be overwritten")


class ConnectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.report_path = self.directory / "connection.json"
        for name, value in (("RECIPIENT_SHA256", release.digest(RECIPIENT.encode())),
                            ("SENDER_SHA256", release.digest(SENDER.encode()))):
            patcher = patch.object(release, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_connection(self, api=None, execute=True):
        api = api or FakeAPI()
        output = io.StringIO()
        args = ["--report", str(self.report_path)] + (["--execute"] if execute else [])
        with patch.object(connection, "API", return_value=api), patch.object(connection.secrets, "token_bytes",
                return_value=GENERATED) as random_bytes, patch("sys.stdout", output):
            status = connection.main(args)
        return status, api, random_bytes, output.getvalue()

    def report(self):
        return json.loads(self.report_path.read_text())

    def test_default_is_read_only_and_never_generates_a_key(self):
        status, api, random_bytes, _ = self.run_connection(execute=False)
        self.assertEqual(status, 0)
        self.assertEqual(api.mutations, [])
        random_bytes.assert_not_called()
        self.assertEqual(self.report()["status"], "reviewed_not_executed")

    def test_adds_only_approved_binding_and_absent_key_without_changing_source_or_other_configuration(self):
        status, api, random_bytes, output = self.run_connection()
        self.assertEqual(status, 0)
        self.assertEqual([(method, path) for method, path, _ in api.mutations], [
            ("POST", release.SCRIPT + "/versions"), ("POST", release.SCRIPT + "/deployments"),
            ("PUT", connection.ROOT + "/secrets")])
        metadata = api.upload["metadata"]
        self.assertEqual(metadata["bindings"], [release.CANARY_BINDING])
        self.assertEqual(metadata["keep_bindings"], sorted(set(release.BINDING_TYPES.values())))
        self.assertEqual(metadata["placement"], {"mode": "smart"})
        for forbidden in ("migrations", "migration_tag", "observability", "logpush", "tail_consumers"):
            self.assertNotIn(forbidden, metadata)
        self.assertEqual(api.upload["source"], VAULT_SOURCE)
        self.assertEqual(api.mutations[1][2]["versions"], [{"version_id": VAULT_NEW, "percentage": 100}])
        self.assertEqual(api.mutations[2][2], {"name": connection.SOURCE_KEY, "type": "secret_text", "text": GENERATED_TEXT})
        random_bytes.assert_called_once_with(32)
        report = self.report()
        self.assertEqual(report["remoteMutations"], 3)
        self.assertEqual(report["phase"], "connection_configuration_verified")
        self.assertTrue(report["sourceAndOtherConfigurationPreserved"])
        self.assertEqual(report["canaryBindingState"], "active_verified")
        self.assertEqual(report["sourceKeyState"], "created_active_verified")
        for marker in (SECRET_MARKER, GENERATED_TEXT, RECIPIENT, SENDER):
            self.assertNotIn(marker, output + self.report_path.read_text())
        self.assertEqual(self.report_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual([path.name for path in self.directory.iterdir()], ["connection.json"])

    def test_existing_configuration_is_idempotent_without_secret_reads_or_writes(self):
        status, api, random_bytes, _ = self.run_connection(FakeAPI(binding=True, key=True))
        self.assertEqual(status, 0)
        self.assertEqual(api.mutations, [])
        random_bytes.assert_not_called()
        self.assertEqual(self.report()["sourceKeyState"], "already_present_value_not_read")
        self.assertEqual(self.report()["canaryBindingState"], "already_present")
        self.assertEqual(self.report()["remoteMutations"], 0)

    def test_each_existing_addition_is_preserved_when_only_the_other_is_absent(self):
        for binding, key, expected_mutations in ((True, False, 1), (False, True, 2)):
            with self.subTest(binding=binding, key=key):
                status, api, random_bytes, _ = self.run_connection(FakeAPI(binding=binding, key=key))
                self.assertEqual(status, 0)
                self.assertEqual(len(api.mutations), expected_mutations)
                if key:
                    random_bytes.assert_not_called()
                    self.assertFalse(any(method == "PUT" for method, _, _ in api.mutations))
                self.report_path.unlink()

    def test_unapproved_existing_binding_or_wrong_key_type_prevents_all_mutations(self):
        for change in ({"service": "other"}, {"entrypoint": "Other"}, {"environment": "staging"}, {"props": {}}):
            with self.subTest(change=change):
                api = FakeAPI(binding=True)
                api.workers[release.SCRIPT]["rows"][VAULT_BASE][-1].update(change)
                self.assertEqual(self.run_connection(api)[0], 1)
                self.assertEqual(api.mutations, [])
                self.report_path.unlink()
        api = FakeAPI(key=True)
        api.workers[connection.ROOT]["rows"][ROOT_BASE][-1]["type"] = "secret_key"
        self.assertEqual(self.run_connection(api)[0], 1)
        self.assertEqual(api.mutations, [])

    def test_absent_etag_is_supported_without_weakening_exact_source_readback(self):
        self.assertEqual(self.run_connection(FakeAPI(failure="no_etag"))[0], 0)

    def test_preflight_and_preupload_drift_stop_without_a_mutation(self):
        for failure in ("split", "preupload_drift", "root_preupload_source"):
            with self.subTest(failure=failure):
                status, api, random_bytes, _ = self.run_connection(FakeAPI(failure=failure))
                self.assertEqual(status, 1)
                self.assertEqual(api.mutations, [])
                random_bytes.assert_not_called()
                self.report_path.unlink()

    def test_uploaded_source_binding_or_preactivation_drift_stops_without_activating(self):
        for failure in ("uploaded_source", "uploaded_binding", "preactivation_drift"):
            with self.subTest(failure=failure):
                status, api, random_bytes, _ = self.run_connection(FakeAPI(failure=failure))
                self.assertEqual(status, 1)
                self.assertEqual(len(api.mutations), 1)
                self.assertEqual(api.workers[release.SCRIPT]["active"], VAULT_BASE)
                random_bytes.assert_not_called()
                self.assertEqual(self.report()["remoteMutations"], 1)
                self.report_path.unlink()

    def test_uncertain_binding_mutations_are_never_retried_or_rolled_back(self):
        for failure, count, phase in (("upload_timeout", 1, "binding_upload_attempt_started"),
                                      ("activation_timeout", 2, "binding_activation_attempt_started")):
            with self.subTest(failure=failure):
                status, api, random_bytes, _ = self.run_connection(FakeAPI(failure=failure))
                self.assertEqual(status, 1)
                self.assertEqual(len(api.mutations), count)
                random_bytes.assert_not_called()
                self.assertIsNone(self.report()["remoteMutations"])
                self.assertEqual(self.report()["phase"], phase)
                self.report_path.unlink()

    def test_key_appearing_before_put_is_not_overwritten(self):
        status, api, random_bytes, _ = self.run_connection(FakeAPI(failure="key_appeared"))
        self.assertEqual(status, 1)
        self.assertEqual(len(api.mutations), 2)
        random_bytes.assert_not_called()
        self.assertEqual(self.report()["reason"], "source_key_presence_changed")
        self.assertEqual(self.report()["canaryBindingState"], "active_verified")

    def test_key_put_uncertainty_reports_the_active_binding_and_never_repeats_the_put(self):
        status, api, _, output = self.run_connection(FakeAPI(failure="key_put_timeout"))
        self.assertEqual(status, 1)
        self.assertEqual(len(api.mutations), 3)
        self.assertIsNone(self.report()["remoteMutations"])
        self.assertEqual(self.report()["phase"], "source_key_put_attempt_started")
        self.assertEqual(self.report()["canaryBindingState"], "active_verified")
        self.assertNotIn(GENERATED_TEXT, output + self.report_path.read_text())

    def test_staged_key_or_root_drift_never_claims_activation_or_retries(self):
        for failure in ("key_staged", "root_source_after_key", "root_settings_after_key"):
            with self.subTest(failure=failure):
                status, api, _, _ = self.run_connection(FakeAPI(failure=failure))
                self.assertEqual(status, 1)
                self.assertEqual(len(api.mutations), 3)
                self.assertEqual(self.report()["remoteMutations"], 3)
                self.assertEqual(self.report()["canaryBindingState"], "active_verified")
                self.assertEqual(self.report()["sourceKeyState"], "creation_acknowledged_activation_unverified")
                self.report_path.unlink()

    def test_existing_report_is_preserved_before_provider_authentication(self):
        self.report_path.write_text("existing evidence")
        with patch.object(connection, "API") as constructor, patch("sys.stdout", io.StringIO()):
            self.assertEqual(connection.main(["--report", str(self.report_path), "--execute"]), 1)
        constructor.assert_not_called()
        self.assertEqual(self.report_path.read_text(), "existing evidence")

    def test_missing_named_rpc_export_prevents_a_connection(self):
        api = FakeAPI()
        api.workers[connection.ROOT]["named"] = [{"name": "KanariyaStore", "handlers": []}]
        self.assertEqual(self.run_connection(api)[0], 1)
        self.assertEqual(api.mutations, [])
        self.assertEqual(self.report()["reason"], "required_worker_exports_changed")

    def test_absent_optional_admin_or_hmac_key_is_not_a_new_configuration_requirement(self):
        api = FakeAPI()
        rows = api.workers[connection.ROOT]["rows"][ROOT_BASE]
        api.workers[connection.ROOT]["rows"][ROOT_BASE] = [row for row in rows if row["name"] not in {"ADMIN_KEY", "IP_HMAC_KEY"}]
        self.assertEqual(self.run_connection(api)[0], 0)

    def test_existing_optional_key_with_unexpected_plaintext_type_is_rejected(self):
        api = FakeAPI()
        next(row for row in api.workers[connection.ROOT]["rows"][ROOT_BASE] if row["name"] == "IP_HMAC_KEY")["type"] = "plain_text"
        self.assertEqual(self.run_connection(api)[0], 1)
        self.assertEqual(api.mutations, [])


if __name__ == "__main__":
    unittest.main()
