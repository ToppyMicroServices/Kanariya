#!/usr/bin/env python3
"""Deploy tested Vault source while preserving the existing production configuration.

Credentials come only from CLOUDFLARE_API_TOKEN/CLOUDFLARE_ACCOUNT_ID. This
helper never fetches secret values or R2 objects, and never changes bindings,
variables, routes, migration settings, or public endpoints. No automatic retry
or rollback is performed when an upload, activation, or readback is uncertain.
R2 public configuration is a separate audit and is not rechecked by this
Worker source release; this helper makes no R2 API requests.
"""
import argparse
import email.policy
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import urllib.error
import urllib.request
import uuid

ACCOUNT = "4ff9cceea79d470ba49cca2a796cf61c"
WORKER = "kanariya-vault"
SCRIPT = f"/accounts/{ACCOUNT}/workers/scripts/{WORKER}"
BUCKET = "kanariya-vault-dummy"
NAMESPACE = "958c3e4236474f7f895e7a6fdbfda6ea"
ZONE = "75453bfdf09e366140301fd7364751cd"
RECIPIENT_SHA256 = "4407860cba3946d91da15b301029c6945a66c5bb51eb1e3eee8327aad5ba6d6d"
SENDER_SHA256 = "47dbb1c443e3761c77c9a45fc77075ae57b6f7177221000cda9340ad0a64b6f1"
HASH = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
BINDING_TYPES = {
    "ACCESS_AUDIENCE": "plain_text", "ACCESS_ISSUER": "plain_text",
    "DUMMY_DOCUMENT_ID": "plain_text", "DUMMY_RECORD_SHA256": "plain_text",
    "PUBLIC_ORIGIN": "plain_text", "VAULT": "durable_object_namespace",
    "VAULT_DOCUMENTS": "r2_bucket", "VAULT_AUDIT_KEY": "secret_text",
    "VAULT_WRAP_KEY": "secret_text", "MAIL_PROVIDER": "plain_text",
    "MAIL_FROM": "secret_text", "MAIL_TO": "secret_text",
    "NOTIFY_EMAIL": "send_email", "PASSWORD_READER_ENABLED": "plain_text",
    "VAULT_OWNER_SUB": "secret_text",
}
CANARY_BINDING = {"name": "CANARY_ADMIN", "type": "service", "service": "kanariya",
                  "entrypoint": "CanaryManagement"}
FIXED_VARS = {
    "PUBLIC_ORIGIN": "https://vault.toppymicros.com",
    "ACCESS_ISSUER": "https://toppymicros.cloudflareaccess.com",
    "ACCESS_AUDIENCE": "31d80e7c6504832419431e62cee2c6fd0fb988ac58b99ddda122528faf7582f3",
    "DUMMY_DOCUMENT_ID": "f025a92a-082d-4eaf-9b78-9ed396b9bb85",
    "DUMMY_RECORD_SHA256": "8f358f97de389893bd7bd1ad0abc1664b260c327aef2198cd6294085c4322cd2",
    "PASSWORD_READER_ENABLED": "1", "MAIL_PROVIDER": "cloudflare",
}
RUNTIME_KEYS = {"migration_tag", "compatibility_date", "compatibility_flags", "usage_model", "limits"}


class SafeFailure(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise SafeFailure(reason)


def digest(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(value).hexdigest()


def regular_path(value):
    path = Path(value).absolute()
    require(path.resolve() == path and path.is_file() and not path.is_symlink(), "regular_artifact_required")
    return path


def evidence(path, report, create=False):
    path = Path(path).absolute()
    require(path.parent.is_dir() and path.parent.resolve() == path.parent, "regular_report_parent_required")
    if create:
        require(not path.exists() and not path.is_symlink(), "new_report_required")
    else:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o600, "report_identity_changed")
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if create:
            # Do not replace an existing path, including a dangling symlink.
            os.link(temporary, path, follow_symlinks=False)
        else:
            temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def local_gate(bundle_path, expected, tests_path):
    require(isinstance(expected, str) and HASH.fullmatch(expected), "exact_candidate_hash_required")
    bundle_path, tests_path = regular_path(bundle_path), regular_path(tests_path)
    body = bundle_path.read_bytes()
    require(0 < len(body) <= 10 * 1024 * 1024 and digest(body) == expected, "candidate_bytes_changed")
    require(tests_path.stat().st_size <= 1024 * 1024, "runtime_report_too_large")
    tests_body = tests_path.read_bytes()
    tested = json.loads(tests_body)
    require(tested.get("status") == "passed" and tested.get("pass") is True and
            tested.get("candidateSha256") == tested.get("candidateSha256After") == expected and
            tested.get("realDataUsed") is False and tested.get("liveNotificationsSent") is False and
            tested.get("compatibilityDate") == "2026-01-12" and
            tested.get("compatibilityFlags") == ["nodejs_compat"], "exact_synthetic_runtime_gate_required")
    return body, digest(tests_body)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise SafeFailure("api_redirect_rejected")


class API:
    def __init__(self):
        require(os.environ.get("CLOUDFLARE_ACCOUNT_ID") == ACCOUNT, "account_identity_mismatch")
        token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
        require(token and "\n" not in token and "\r" not in token, "existing_api_token_required")
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def __call__(self, path, method="GET", data=None, content_type=None, raw=False):
        require(path.startswith("/") and not path.startswith("//"), "api_path_invalid")
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}
        if isinstance(data, dict):
            data = json.dumps(data).encode()
            content_type = "application/json"
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request("https://api.cloudflare.com/client/v4" + path,
                                         data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=30) as response:
                body = response.read(20 * 1024 * 1024 + 1)
                require(len(body) <= 20 * 1024 * 1024, "api_response_too_large")
                if raw:
                    return response.headers.get("Content-Type", ""), body
                value = json.loads(body)
        except urllib.error.HTTPError as error:
            codes = []
            try:
                value = json.loads(error.read(1024 * 1024))
                codes = [item["code"] for item in value.get("errors", [])
                         if isinstance(item, dict) and type(item.get("code")) is int]
            except Exception:
                pass
            finally:
                error.close()
            failure = SafeFailure(f"api_http_{error.code}")
            failure.http_status, failure.api_codes = error.code, codes
            failure.api_resource = "worker_or_zone_metadata"
            raise failure from None
        except (urllib.error.URLError, TimeoutError):
            raise SafeFailure("api_transport_unknown") from None
        require(isinstance(value, dict) and value.get("success") is True and "result" in value,
                "api_result_not_successful")
        return value["result"]


def checked_binding_types(value):
    require(isinstance(value, list) and all(isinstance(row, dict) and
            isinstance(row.get("name"), str) and isinstance(row.get("type"), str)
            for row in value), "binding_metadata_invalid")
    types = {row["name"]: row["type"] for row in value}
    expected = dict(BINDING_TYPES)
    if CANARY_BINDING["name"] in types:
        expected[CANARY_BINDING["name"]] = CANARY_BINDING["type"]
    require(len(value) == len(expected) and types == expected, "binding_names_or_types_changed")
    by_name = {row["name"]: row for row in value}
    if CANARY_BINDING["name"] in by_name:
        canary = by_name[CANARY_BINDING["name"]]
        require(set(canary) in (set(CANARY_BINDING), set(CANARY_BINDING) | {"environment"}) and
                all(canary.get(key) == item for key, item in CANARY_BINDING.items()) and
                ("environment" not in canary or canary["environment"] == "production"),
                "canary_service_binding_changed")
    return sorted(set(types.values()))


def checked_bindings(value):
    checked_binding_types(value)
    by_name = {row["name"]: row for row in value}
    for name, expected in FIXED_VARS.items():
        require(by_name[name].get("text") == expected, "approved_auth_or_dummy_configuration_changed")
    require(by_name["VAULT_DOCUMENTS"].get("bucket_name") == BUCKET, "dummy_bucket_binding_changed")
    require(by_name["VAULT"].get("namespace_id") == NAMESPACE and
            by_name["VAULT"].get("class_name") == "VaultDocument", "durable_object_binding_changed")
    email = by_name["NOTIFY_EMAIL"]
    target = email.get("destination_address")
    senders = email.get("allowed_sender_addresses")
    require(isinstance(target, str) and digest(target.encode()) == RECIPIENT_SHA256 and
            isinstance(senders, list) and len(senders) == 1 and isinstance(senders[0], str) and
            digest(senders[0].encode()) == SENDER_SHA256 and
            email.get("allowed_destination_addresses") in (None, []), "notification_restriction_changed")
    # Only the digest leaves this function. Discard unexpected secret-value fields.
    rows = [{key: item for key, item in row.items() if row["type"] != "secret_text" or
             key not in ("text", "key_base64", "key_jwk")} for row in value]
    return digest(sorted(rows, key=lambda row: row["name"]))


def version_id(value):
    require(isinstance(value, str) and VERSION.fullmatch(value), "version_identity_invalid")
    return value


def active(api):
    value = api(SCRIPT + "/deployments")
    rows = value.get("deployments", []) if isinstance(value, dict) else value
    require(isinstance(rows, list) and rows, "deployment_metadata_missing")
    versions = rows[0].get("versions", [])
    require(len(versions) == 1 and versions[0].get("percentage") == 100, "split_deployment_preserved")
    return version_id(versions[0].get("version_id"))


def latest(api):
    value = api(SCRIPT + "/versions")
    rows = value.get("items", []) if isinstance(value, dict) else value
    require(isinstance(rows, list) and rows, "latest_version_missing")
    return version_id(rows[0].get("id"))


def detail(api, version):
    value = api(SCRIPT + "/versions/" + version)
    require(value.get("id") == version, "version_identity_changed")
    resources = value.get("resources") or {}
    runtime = dict(resources.get("script_runtime") or {})
    require(set(runtime) <= RUNTIME_KEYS and runtime.get("migration_tag") == "v1-vault" and
            runtime.get("compatibility_date") == "2026-01-12" and
            runtime.get("compatibility_flags") == ["nodejs_compat"] and
            runtime.get("usage_model") == "standard", "tested_runtime_changed")
    script = resources.get("script") or {}
    return {"bindingsSha256": checked_bindings(resources.get("bindings")),
            "bindingTypes": checked_binding_types(resources.get("bindings")), "runtime": runtime,
            "handlersSha256": digest({"handlers": script.get("handlers"), "namedHandlers": script.get("named_handlers")})}


def source(api):
    content_type, body = api(SCRIPT + "/content/v2", raw=True)
    message = BytesParser(policy=email.policy.default).parsebytes(
        ("Content-Type: " + content_type + "\r\nMIME-Version: 1.0\r\n\r\n").encode() + body)
    require(message.is_multipart(), "source_metadata_invalid")
    parts = list(message.iter_parts())
    require(len(parts) == 1 and parts[0].get_param("name", header="content-disposition") == "worker.js" and
            parts[0].get_content_type() == "application/javascript+module", "source_modules_changed")
    body = parts[0].get_payload(decode=True)
    require(isinstance(body, bytes), "source_metadata_invalid")
    return digest(body)


def worker_endpoints(api):
    subdomain = api(SCRIPT + "/subdomain")
    require(subdomain.get("enabled") is False and subdomain.get("previews_enabled") is False, "public_endpoint_changed")
    domains = api(f"/accounts/{ACCOUNT}/workers/domains")
    require(isinstance(domains, list), "domain_metadata_invalid")
    assigned = [row for row in domains if row.get("service") == WORKER]
    require(len(assigned) == 1 and assigned[0].get("hostname") == "vault.toppymicros.com" and
            assigned[0].get("environment") == "production", "approved_custom_domain_changed")
    zones = []
    for page in range(1, 5):
        rows = api(f"/zones?account.id={ACCOUNT}&per_page=50&page={page}")
        require(isinstance(rows, list) and all(row.get("account", {}).get("id") == ACCOUNT for row in rows),
                "zone_scope_invalid")
        zones.extend(row["id"] for row in rows)
        if len(rows) < 50:
            break
    else:
        raise SafeFailure("zone_enumeration_limit_reached")
    require(ZONE in zones and len(zones) == len(set(zones)), "approved_zone_coverage_unknown")
    for zone in sorted(zones):
        rows = api(f"/zones/{zone}/workers/routes")
        require(isinstance(rows, list) and not any(row.get("script") == WORKER for row in rows), "vault_zone_route_changed")
    return {"endpointsSha256": digest({"subdomain": subdomain, "assignedDomains": assigned, "zones": sorted(zones)})}


def snapshot(api, expected_active, expected_latest):
    require(active(api) == expected_active and latest(api) == expected_latest, "version_drift")
    settings = api(SCRIPT + "/settings")
    bindings = checked_bindings(settings.get("bindings"))
    stable = {key: item for key, item in settings.items() if key not in ("bindings", "annotations")}
    flags_present = "compatibility_flags" in stable
    flags = stable.pop("compatibility_flags", None)
    result = {"activeDetail": detail(api, expected_active), "latestDetail": detail(api, expected_latest),
              "bindingsSha256": bindings, "settingsSha256": digest(stable),
              "settingsFlagsPresent": flags_present, "settingsFlags": flags,
              "sourceSha256": source(api), **worker_endpoints(api)}
    require(result["activeDetail"]["bindingsSha256"] == result["latestDetail"]["bindingsSha256"] == bindings,
            "active_current_binding_drift")
    require(active(api) == expected_active and latest(api) == expected_latest, "state_changed_during_readback")
    return result


def unchanged(observed, baseline, expected_source):
    require(observed["sourceSha256"] == expected_source, "source_readback_mismatch")
    for key in ("activeDetail", "latestDetail", "bindingsSha256", "settingsSha256",
                "settingsFlagsPresent", "settingsFlags", "endpointsSha256"):
        require(observed[key] == baseline[key], "configuration_changed")


def multipart(body, runtime, binding_types):
    # Retain an existing, validated service binding; this never creates one.
    metadata = {"main_module": "worker.js", "keep_bindings": binding_types,
                **{key: value for key, value in runtime.items() if key != "migration_tag"}}
    boundary = "kanariya-vault-source-" + uuid.uuid4().hex
    parts = []
    for name, mime, value in (("metadata", "application/json", json.dumps(metadata).encode()),
                              ("worker.js", "application/javascript+module", body)):
        filename = '; filename="worker.js"' if name == "worker.js" else ""
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"{filename}\r\n'
                      f'Content-Type: {mime}\r\n\r\n').encode() + value + b"\r\n")
    return b"".join(parts) + f"--{boundary}--\r\n".encode(), boundary


def deploy(api, body, report, report_path):
    report.update(phase="read_only_preflight")
    evidence(report_path, report)
    base = active(api)
    require(latest(api) == base, "active_is_not_latest_upload")
    baseline = snapshot(api, base, base)
    report.update(phase="preflight_verified", baseVersion=base, baseline=baseline)
    evidence(report_path, report)
    # Recheck immediately before the first mutation, including concurrent changes.
    unchanged(snapshot(api, base, base), baseline, baseline["sourceSha256"])
    data, boundary = multipart(body, baseline["latestDetail"]["runtime"], baseline["latestDetail"]["bindingTypes"])
    report.update(phase="upload_attempt_started", remoteMutations=None)
    evidence(report_path, report)
    created = api(SCRIPT + "/versions", method="POST", data=data,
                  content_type="multipart/form-data; boundary=" + boundary)
    version = version_id(created.get("id"))
    require(version != base, "new_version_not_created")
    report.update(phase="uploaded_not_active", uploadedVersion=version, remoteMutations=1)
    evidence(report_path, report)
    unchanged(snapshot(api, base, version), baseline, report["candidateSha256"])
    report.update(phase="uploaded_verified_not_active")
    evidence(report_path, report)
    unchanged(snapshot(api, base, version), baseline, report["candidateSha256"])
    report.update(phase="activation_attempt_started", remoteMutations=None)
    evidence(report_path, report)
    api(SCRIPT + "/deployments", method="POST", data={"strategy": "percentage",
        "versions": [{"version_id": version, "percentage": 100}]})
    report.update(phase="activation_acknowledged", remoteMutations=2)
    evidence(report_path, report)
    unchanged(snapshot(api, version, version), baseline, report["candidateSha256"])
    report.update(phase="active_source_and_configuration_verified", status="passed", percentage=100,
                  sourceBindingsRuntimeAndWorkerEndpointsVerified=True)
    evidence(report_path, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--tests", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args(argv)
    report = {"status": "running_not_verified", "phase": "local_gate", "worker": WORKER,
              "remoteMutations": 0, "workerSecretValuesRead": False, "varsOrSecretsWritten": False,
              "r2ApiRequests": 0, "r2ObjectsAccessed": False, "r2ConfigurationWritten": False,
              "r2PublicConfigurationVerified": False,
              "r2PublicConfiguration": "not_rechecked_source_only_release", "notificationsSent": 0,
              "automaticRetry": False, "automaticRollback": False}
    report_created = False
    try:
        body, tests_sha = local_gate(args.bundle, args.sha256, args.tests)
        report.update(candidateSha256=digest(body), testsSha256=tests_sha)
        evidence(args.report, report, create=True)
        report_created = True
        result = deploy(API(), body, report, args.report)
        print(json.dumps({key: result[key] for key in ("status", "phase", "candidateSha256", "uploadedVersion", "percentage")}))
        return 0
    except Exception as error:
        reason = str(error) if isinstance(error, SafeFailure) else "unexpected_error_details_redacted"
        report.update(status="stopped_preserve_state", failedDuringPhase=report["phase"], reason=reason)
        if isinstance(error, SafeFailure) and hasattr(error, "http_status"):
            report.update(httpStatus=error.http_status, apiErrorCodes=error.api_codes, apiResource=error.api_resource)
        if report_created:
            try:
                evidence(args.report, report)
            except Exception:
                pass  # Preserve the last durable phase; do not mask the original failure.
        print(json.dumps({"status": report["status"], "phase": report["phase"], "reason": reason,
                          "remoteMutations": report["remoteMutations"], "detailsRedacted": True,
                          **{key: report[key] for key in ("httpStatus", "apiErrorCodes", "apiResource") if key in report}}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
