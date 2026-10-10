#!/usr/bin/env python3
"""Connect the reviewed production Canary RPC and add its separate source key.

Default execution is read-only. --execute adds only CANARY_ADMIN on the existing
Vault source and CANARY_SOURCE_KEY on kanariya, if each is absent. Credentials
come from the existing Cloudflare CI token. Secret values are never fetched;
the new 32-byte key is generated only in memory and is never printed or saved.
There is no automatic retry, rollback, or R2/Access operation.

Official API contracts:
https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/create/
https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/create/
https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/methods/update/
"""
import argparse
import base64
import copy
import email.policy
from email.parser import BytesParser
import importlib.util
import json
import os
from pathlib import Path
import secrets
import uuid

SPEC = importlib.util.spec_from_file_location("canary_source_release", Path(__file__).with_name("deploy_vault_source.py"))
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
API, SafeFailure, require, digest = release.API, release.SafeFailure, release.require, release.digest
ROOT = f"/accounts/{release.ACCOUNT}/workers/scripts/kanariya"
SOURCE_KEY = "CANARY_SOURCE_KEY"
SECRET_FIELDS = {"text", "key_base64", "key_jwk"}
STABLE_KEYS = {"settingsSha256", "preservedBindingsSha256", "activeDetail", "latestDetail",
               "sourceSha256", "endpointsSha256"}


def active(api, script):
    value = api(script + "/deployments")
    rows = value.get("deployments", []) if isinstance(value, dict) else value
    require(isinstance(rows, list) and rows, "deployment_metadata_missing")
    versions = rows[0].get("versions", [])
    require(len(versions) == 1 and versions[0].get("percentage") == 100, "split_deployment_preserved")
    return release.version_id(versions[0].get("version_id"))


def latest(api, script):
    value = api(script + "/versions")
    rows = value.get("items", []) if isinstance(value, dict) else value
    require(isinstance(rows, list) and rows, "latest_version_missing")
    return release.version_id(rows[0].get("id"))


def source_bytes(api, script):
    content_type, encoded = api(script + "/content/v2", raw=True)
    require(isinstance(content_type, str) and "\r" not in content_type and "\n" not in content_type and
            isinstance(encoded, bytes) and len(encoded) <= 11 * 1024 * 1024, "source_metadata_invalid")
    message = BytesParser(policy=email.policy.default).parsebytes(
        ("Content-Type: " + content_type + "\r\nMIME-Version: 1.0\r\n\r\n").encode() + encoded)
    require(message.is_multipart(), "source_metadata_invalid")
    parts = list(message.iter_parts())
    require(len(parts) == 1 and parts[0].get_param("name", header="content-disposition") == "worker.js" and
            parts[0].get_content_type() == "application/javascript+module", "source_modules_changed")
    body = parts[0].get_payload(decode=True)
    require(isinstance(body, bytes) and 0 < len(body) <= 10 * 1024 * 1024, "source_metadata_invalid")
    return body


def checked_rows(rows, vault):
    require(isinstance(rows, list) and all(isinstance(row, dict) and isinstance(row.get("name"), str) and
            isinstance(row.get("type"), str) for row in rows), "binding_metadata_invalid")
    require(len(rows) == len({row["name"] for row in rows}), "duplicate_binding_metadata")
    optional = release.CANARY_BINDING["name"] if vault else SOURCE_KEY
    present = any(row["name"] == optional for row in rows)
    if vault:
        release.checked_bindings(rows)
        preserved = [row for row in rows if row["name"] != optional]
        fingerprint = release.checked_bindings(preserved)
    else:
        kinds = {row["name"]: row["type"] for row in rows}
        require(all(row["type"] in {"plain_text", "secret_text", "kv_namespace", "durable_object_namespace"}
                    for row in rows) and
                all(name not in kinds or kinds[name] == "secret_text" for name in ("ADMIN_KEY", "IP_HMAC_KEY")) and
                kinds.get("KANARI_STORE") == "durable_object_namespace" and
                kinds.get("KANARI_KV") == "kv_namespace", "canary_core_bindings_changed")
        store = next(row for row in rows if row["name"] == "KANARI_STORE")
        require(store.get("class_name") == "KanariyaStore", "canary_store_class_changed")
        if present:
            key = next(row for row in rows if row["name"] == optional)
            require(key["type"] == "secret_text" and set(key) <= {"name", "type"} | SECRET_FIELDS,
                    "source_key_binding_invalid")
        preserved = [{key: item for key, item in row.items() if row["type"] != "secret_text" or key not in SECRET_FIELDS}
                     for row in rows if row["name"] != optional]
        fingerprint = digest(sorted(preserved, key=lambda row: row["name"]))
    return fingerprint, present, sorted({row["type"] for row in rows})


def detail(api, script, version, vault, expected_present):
    value = api(script + "/versions/" + version)
    require(isinstance(value, dict) and value.get("id") == version, "version_identity_changed")
    resources = value.get("resources") or {}
    fingerprint, present, types = checked_rows(resources.get("bindings"), vault)
    require(present is expected_present, "approved_binding_presence_changed")
    runtime = dict(resources.get("script_runtime") or {})
    expected_tag = "v1-vault" if vault else "v1-kanariya-store"
    expected_flags = ["nodejs_compat"] if vault else []
    require(set(runtime) <= release.RUNTIME_KEYS and runtime.get("migration_tag") == expected_tag and
            runtime.get("compatibility_date") == "2026-01-12" and
            runtime.get("compatibility_flags", []) == expected_flags and
            runtime.get("usage_model") in ({"standard"} if vault else {"standard", "bundled", "unbound"}),
            "tested_runtime_changed")
    script_metadata = resources.get("script") or {}
    handlers = script_metadata.get("handlers")
    named = script_metadata.get("named_handlers")
    expected_named = {"VaultDocument"} if vault else {"KanariyaStore", "CanaryManagement"}
    require(handlers == ["fetch"] and isinstance(named, list) and len(named) == len(expected_named) and
            all(isinstance(row, dict) and isinstance(row.get("name"), str) and
                isinstance(row.get("handlers"), list) and all(isinstance(handler, str) for handler in row["handlers"])
                for row in named) and {row["name"] for row in named} == expected_named,
            "required_worker_exports_changed")
    etag = script_metadata.get("etag")
    require(etag is None or isinstance(etag, str) and 0 < len(etag) <= 256, "version_source_etag_invalid")
    return {"preservedBindingsSha256": fingerprint, "runtime": runtime,
            "handlersSha256": digest({"handlers": handlers, "namedHandlers": named}),
            "sourceEtagSha256": digest({"present": "etag" in script_metadata, "value": etag})}, types


def root_endpoints(api):
    subdomain = api(ROOT + "/subdomain")
    require(isinstance(subdomain, dict), "canary_subdomain_metadata_invalid")
    domains = api(f"/accounts/{release.ACCOUNT}/workers/domains")
    require(isinstance(domains, list), "domain_metadata_invalid")
    assigned = [row for row in domains if row.get("service") == "kanariya"]
    zones = []
    routes = {}
    for page in range(1, 5):
        rows = api(f"/zones?account.id={release.ACCOUNT}&per_page=50&page={page}")
        require(isinstance(rows, list) and all(row.get("account", {}).get("id") == release.ACCOUNT for row in rows),
                "zone_scope_invalid")
        zones.extend(row["id"] for row in rows)
        if len(rows) < 50:
            break
    else:
        raise SafeFailure("zone_enumeration_limit_reached")
    require(release.ZONE in zones and len(zones) == len(set(zones)), "approved_zone_coverage_unknown")
    for zone in sorted(zones):
        rows = api(f"/zones/{zone}/workers/routes")
        require(isinstance(rows, list), "route_metadata_invalid")
        routes[zone] = [row for row in rows if row.get("script") == "kanariya"]
    return {"endpointsSha256": digest({"subdomain": subdomain, "assignedDomains": assigned, "routes": routes})}


def snapshot(api, script, expected_active, expected_latest, vault, active_present, latest_present):
    require(active(api, script) == expected_active and latest(api, script) == expected_latest, "version_drift")
    settings = api(script + "/settings")
    require(isinstance(settings, dict), "settings_metadata_invalid")
    fingerprint, present, types = checked_rows(settings.get("bindings"), vault)
    require(present in (active_present, latest_present), "approved_binding_presence_changed")
    stable = {key: item for key, item in settings.items() if key not in ("bindings", "annotations")}
    old, _ = detail(api, script, expected_active, vault, active_present)
    new, _ = detail(api, script, expected_latest, vault, latest_present)
    require(old["preservedBindingsSha256"] == new["preservedBindingsSha256"] == fingerprint,
            "other_bindings_changed")
    require(old == new, "runtime_exports_or_version_source_changed")
    body = source_bytes(api, script)
    endpoints = release.worker_endpoints(api) if vault else root_endpoints(api)
    require(active(api, script) == expected_active and latest(api, script) == expected_latest,
            "state_changed_during_readback")
    upload_settings = {}
    if stable.get("placement") is not None:
        require(isinstance(stable["placement"], dict) and stable["placement"].get("mode") == "smart",
                "placement_upload_contract_unknown")
        upload_settings["placement"] = copy.deepcopy(stable["placement"])
    return {"settingsSha256": digest(stable), "preservedBindingsSha256": fingerprint,
            "activeDetail": old, "latestDetail": new, "sourceSha256": digest(body),
            "bindingTypes": types, **endpoints}, body, upload_settings


def unchanged(observed, baseline):
    require(all(observed[key] == baseline[key] for key in STABLE_KEYS), "other_configuration_changed")


def secret_present(api):
    rows = api(ROOT + "/secrets")  # List metadata only; never call /secrets/<name>.
    require(isinstance(rows, list) and all(isinstance(row, dict) and isinstance(row.get("name"), str) and
            row.get("type") in {"secret_text", "secret_key"} for row in rows), "secret_name_metadata_invalid")
    require(len(rows) == len({row["name"] for row in rows}), "duplicate_secret_names")
    matches = [row for row in rows if row["name"] == SOURCE_KEY]
    require(not matches or matches[0]["type"] == "secret_text", "source_key_type_changed")
    return bool(matches)


def multipart(body, runtime, binding_types, upload_settings):
    metadata = {"main_module": "worker.js", "bindings": [dict(release.CANARY_BINDING)],
                "keep_bindings": binding_types,
                **{key: value for key, value in runtime.items() if key != "migration_tag"},
                **upload_settings}
    boundary = "kanariya-reviewed-connection-" + uuid.uuid4().hex
    parts = []
    for name, mime, value in (("metadata", "application/json", json.dumps(metadata).encode()),
                              ("worker.js", "application/javascript+module", body)):
        filename = '; filename="worker.js"' if name == "worker.js" else ""
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"{filename}\r\n'
                      f'Content-Type: {mime}\r\n\r\n').encode() + value + b"\r\n")
    return b"".join(parts) + f"--{boundary}--\r\n".encode(), boundary


def configure(api, report, report_path, execute=False):
    def save(phase, **fields):
        report.update(phase=phase, **fields)
        release.evidence(report_path, report)

    save("read_only_preflight")
    vault_base, root_base = active(api, release.SCRIPT), active(api, ROOT)
    require(latest(api, release.SCRIPT) == vault_base and latest(api, ROOT) == root_base,
            "active_is_not_latest_upload")
    # Determine only the approved additions' metadata, then validate every
    # existing binding, source module, runtime setting and endpoint.
    vault_rows = api(release.SCRIPT + "/settings").get("bindings")
    _, has_binding, _ = checked_rows(vault_rows, True)
    has_key = secret_present(api)
    vault_baseline, body, upload_settings = snapshot(api, release.SCRIPT, vault_base, vault_base, True, has_binding, has_binding)
    root_baseline, _, _ = snapshot(api, ROOT, root_base, root_base, False, has_key, has_key)
    save("preflight_verified", vaultBaseVersion=vault_base, rootBaseVersion=root_base,
         vaultBaseline=vault_baseline, rootBaseline=root_baseline,
         canaryBindingState="already_present" if has_binding else "absent",
         sourceKeyState="already_present_value_not_read" if has_key else "absent")
    if not execute:
        save("dry_run_complete", status="reviewed_not_executed")
        return report
    unchanged(snapshot(api, ROOT, root_base, root_base, False, has_key, has_key)[0], root_baseline)
    require(secret_present(api) is has_key, "source_key_presence_changed")
    unchanged(snapshot(api, release.SCRIPT, vault_base, vault_base, True, has_binding, has_binding)[0], vault_baseline)
    vault_current = vault_base
    if not has_binding:
        payload, boundary = multipart(body, vault_baseline["latestDetail"]["runtime"],
                                      vault_baseline["bindingTypes"], upload_settings)
        save("binding_upload_attempt_started", remoteMutations=None)
        created = api(release.SCRIPT + "/versions", method="POST", data=payload,
                      content_type="multipart/form-data; boundary=" + boundary)
        vault_current = release.version_id(created.get("id"))
        require(vault_current != vault_base, "new_version_not_created")
        save("binding_uploaded_not_active", vaultUploadedVersion=vault_current, remoteMutations=1,
             canaryBindingState="uploaded_not_active")
        unchanged(snapshot(api, release.SCRIPT, vault_base, vault_current, True, False, True)[0], vault_baseline)
        save("binding_verified_not_active")
        unchanged(snapshot(api, release.SCRIPT, vault_base, vault_current, True, False, True)[0], vault_baseline)
        save("binding_activation_attempt_started", remoteMutations=None)
        api(release.SCRIPT + "/deployments", method="POST", data={"strategy": "percentage",
            "versions": [{"version_id": vault_current, "percentage": 100}]})
        save("binding_activation_acknowledged", remoteMutations=2, canaryBindingState="activation_acknowledged")
        unchanged(snapshot(api, release.SCRIPT, vault_current, vault_current, True, True, True)[0], vault_baseline)
        save("binding_active_verified", canaryBindingState="active_verified", vaultActiveVersion=vault_current)
    unchanged(snapshot(api, ROOT, root_base, root_base, False, has_key, has_key)[0], root_baseline)
    require(secret_present(api) is has_key, "source_key_presence_changed")
    if not has_key:
        completed = report["remoteMutations"]
        key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        save("source_key_put_attempt_started", remoteMutations=None)
        # The generated value exists only in this process and this HTTPS PUT.
        try:
            result = api(ROOT + "/secrets", method="PUT", data={"name": SOURCE_KEY, "type": "secret_text", "text": key})
        finally:
            key = None
        save("source_key_put_acknowledged", remoteMutations=completed + 1,
             sourceKeyState="creation_acknowledged_activation_unverified")
        require(isinstance(result, dict) and result.get("name") == SOURCE_KEY and result.get("type") == "secret_text",
                "source_key_acknowledgement_invalid")
        require(secret_present(api), "source_key_not_present_after_put")
        root_current = active(api, ROOT)
        require(root_current != root_base and latest(api, ROOT) == root_current,
                "source_key_version_activation_unverified")
        unchanged(snapshot(api, ROOT, root_current, root_current, False, True, True)[0], root_baseline)
        save("source_key_active_verified", sourceKeyState="created_active_verified", rootActiveVersion=root_current)
    else:
        report["rootActiveVersion"] = root_base
    unchanged(snapshot(api, release.SCRIPT, vault_current, vault_current, True, True, True)[0], vault_baseline)
    save("connection_configuration_verified", status="passed", vaultActiveVersion=vault_current,
         sourceAndOtherConfigurationPreserved=True, canaryBindingConfigured=True, sourceKeyConfigured=True)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True)
    parser.add_argument("--execute", action="store_true", help="Apply the approved binding and absent key only")
    args = parser.parse_args(argv)
    report = {"status": "running_not_verified", "phase": "local_gate", "remoteMutations": 0,
              "workerSecretValuesRead": False, "keyMaterialWrittenToDisk": False,
              "existingSourceKeyOverwritten": False, "serverSideCompareAndSwap": False,
              "accessConfigurationWritten": False, "routesOrDomainsWritten": False,
              "r2ApiRequests": 0, "r2ObjectsAccessed": False, "notificationsSent": 0,
              "automaticRetry": False, "automaticRollback": False,
              "canaryBindingState": "not_checked", "sourceKeyState": "not_checked"}
    created = False
    try:
        release.evidence(args.report, report, create=True)
        created = True
        result = configure(API(), report, args.report, args.execute)
        print(json.dumps({key: result[key] for key in ("status", "phase", "remoteMutations",
                          "canaryBindingState", "sourceKeyState")}))
        return 0
    except Exception as error:
        reason = str(error) if isinstance(error, SafeFailure) else "unexpected_error_details_redacted"
        report.update(status="stopped_preserve_state", failedDuringPhase=report["phase"], reason=reason)
        if isinstance(error, SafeFailure) and hasattr(error, "http_status"):
            report.update(httpStatus=error.http_status, apiErrorCodes=error.api_codes, apiResource=error.api_resource)
        if created:
            try:
                release.evidence(args.report, report)
            except Exception:
                pass
        print(json.dumps({key: report[key] for key in ("status", "phase", "reason", "remoteMutations",
                          "canaryBindingState", "sourceKeyState")}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
