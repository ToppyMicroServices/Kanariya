#!/usr/bin/env python3
"""Review an owner-prepared synthetic replacement; default to read-only preflight.

--execute requires --approve equal to the SHA-256 of the exact 13-field plan
file. This is a separate, explicitly approved change to the two dummy pins;
it never enables arbitrary documents, adds bindings, reads R2, or changes keys.
The current source and other 13 bindings are retained. The source-only release
helper's approved pin baseline must be reviewed separately after a successful
rotation; this tool does not edit that helper or commit any configuration.

Cloudflare's version API keeps bindings by TYPE. We retain every non-plain-text
type and explicitly repeat all seven existing plain-text variables, changing
only the two pins. See the official Upload Version API's keep_bindings field:
https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/create/

Repeated active/latest checks detect drift, but the deployment API does not
document a server-side compare-and-swap. Run only with other releases paused.
There is no automatic retry or rollback after an uncertain provider response.
No live run is implied by preparing or testing this helper.
"""
import argparse
import copy
import email.policy
from email.parser import BytesParser
import importlib.util
import json
import os
from pathlib import Path
import re
import time
import uuid

_SPEC = importlib.util.spec_from_file_location(
    "kanariya_source_release", Path(__file__).resolve().with_name("deploy_vault_source.py"))
release = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(release)
SafeFailure, require, digest = release.SafeFailure, release.require, release.digest
API = release.API
PIN_NAMES = {"DUMMY_DOCUMENT_ID", "DUMMY_RECORD_SHA256"}
PLAN_FIELDS = {"version", "status", "id", "currentDocumentId", "currentRecordSha256",
               "recordSha256", "preparedSha256", "sourceSha256", "watermarkEnabled",
               "expiresAt", "authMode", "registryRevision", "createdAt"}
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
RENDERERS = ("poppler", "pdfkit", "pdfium")
MAX_PDF = 1024 * 1024
MAX_PAGES = 20


def now_ms():
    return int(time.time() * 1000)


def read_artifact(path, maximum, reason):
    """Read a bounded regular artifact without following a replaced symlink."""
    path = release.regular_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        require(0 < before.st_size <= maximum, reason)
        body = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    require(len(body) == before.st_size and
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "artifact_changed_during_read")
    return body


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_field")
        result[key] = value
    return result


def json_artifact(path, maximum, reason):
    body = read_artifact(path, maximum, reason)
    try:
        value = json.loads(body, object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(SafeFailure("invalid_json_constant")))
    except (UnicodeError, ValueError):
        raise SafeFailure("artifact_json_invalid") from None
    require(isinstance(value, dict), "artifact_json_object_required")
    return value, digest(body)


def valid_time(value):
    return type(value) is int and 0 < value <= 9007199254740991


def check_expiry(plan):
    require(plan["expiresAt"] > now_ms(), "replacement_expired")


def checked_plan(path):
    plan, sha = json_artifact(path, 16 * 1024, "plan_too_large")
    require(set(plan) == PLAN_FIELDS and type(plan.get("version")) is int and plan["version"] == 1 and
            plan.get("status") == "prepared_not_active", "exact_neutral_plan_required")
    require(all(isinstance(plan[key], str) and UUID4.fullmatch(plan[key]) for key in ("id", "currentDocumentId")) and
            plan["id"] != plan["currentDocumentId"], "distinct_dummy_identity_required")
    require(all(isinstance(plan[key], str) and release.HASH.fullmatch(plan[key]) for key in
                ("currentRecordSha256", "recordSha256", "preparedSha256", "sourceSha256")) and
            plan["recordSha256"] != plan["currentRecordSha256"], "exact_record_hashes_required")
    require(plan["currentDocumentId"] == release.FIXED_VARS["DUMMY_DOCUMENT_ID"] and
            plan["currentRecordSha256"] == release.FIXED_VARS["DUMMY_RECORD_SHA256"], "approved_current_pins_required")
    require(type(plan["watermarkEnabled"]) is bool and plan["authMode"] == "password" and
            valid_time(plan["expiresAt"]) and valid_time(plan["createdAt"]) and
            plan["createdAt"] <= now_ms() and plan["createdAt"] < plan["expiresAt"] and
            type(plan["registryRevision"]) is int and 2 <= plan["registryRevision"] <= 9007199254740991,
            "replacement_policy_invalid")
    check_expiry(plan)
    return plan, sha


def relative_artifact(root, value):
    require(isinstance(value, str) and value and not Path(value).is_absolute() and
            all(part not in ("..", ".") for part in Path(value).parts), "qa_artifact_path_invalid")
    path = root / value
    require(path.resolve().is_relative_to(root.resolve()), "qa_artifact_path_invalid")
    return path


def checked_qa(pdf_path, qa_path, plan):
    pdf = read_artifact(pdf_path, MAX_PDF, "final_pdf_size_invalid")
    require(pdf.startswith(b"%PDF-") and digest(pdf) == plan["preparedSha256"], "exact_final_pdf_required")
    qa, sha = json_artifact(qa_path, 1024 * 1024, "qa_report_too_large")
    require(type(qa.get("schema_version")) is int and qa["schema_version"] == 1 and qa.get("status") == "verified" and
            qa.get("sha256") == plan["preparedSha256"] and type(qa.get("bytes")) is int and qa["bytes"] == len(pdf) and
            qa.get("source") == "Entirely synthetic; no real CV or personal data was read." and
            qa.get("warnings") == [], "exact_synthetic_verified_qa_required")
    checks = qa.get("checks")
    require(isinstance(checks, dict) and checks and
            all(isinstance(value, dict) and value.get("passed") is True for value in checks.values()),
            "all_qa_checks_must_pass")
    mandatory = {"synthetic_content", "expected_page_count", "no_interactive_content",
                 "no_pdf_open_callback_or_external_reference_objects", "source_bytes_unchanged", "visual_review"}
    require(mandatory <= set(checks) and checks["source_bytes_unchanged"].get("final_sha256") == plan["preparedSha256"] and
            checks["visual_review"].get("artifact_and_image_hashes_match") is True, "complete_final_pdf_qa_required")
    pages = checks["expected_page_count"].get("page_count")
    require(type(pages) is int and 1 <= pages <= MAX_PAGES, "all_page_qa_required")
    for name in ("qpdf_structure", "ghostscript_structure"):
        item = checks.get(name, {})
        require(item.get("passed") is True and type(item.get("exit_code")) is int and item["exit_code"] == 0 and
                item.get("structural_warnings") == [], "zero_structural_warnings_required")
    require(isinstance(qa.get("renderers"), dict) and set(RENDERERS) <= set(qa["renderers"]),
            "three_independent_renderers_required")
    for name in RENDERERS:
        item = checks.get(name + "_all_pages", {})
        require(item.get("passed") is True and type(item.get("rendered_pages")) is int and item["rendered_pages"] == pages and
                isinstance(qa["renderers"][name], dict) and qa["renderers"][name] and
                checks.get(name + "_nonblank", {}).get("passed") is True and
                ("exit_code" not in item or type(item["exit_code"]) is int and item["exit_code"] == 0),
                "three_independent_all_page_renders_required")
    mark = checks.get("recipient_raster_on_every_page", {})
    if plan["watermarkEnabled"]:
        require(mark.get("passed") is True and type(mark.get("pages_checked")) is int and mark["pages_checked"] == pages,
                "every_page_watermark_qa_required")
    else:
        require(qa.get("watermark_enabled") is False and not mark, "unwatermarked_qa_required")
    images = qa.get("images")
    require(isinstance(images, list) and len(images) == pages * len(RENDERERS), "all_page_images_required")
    root = release.regular_path(qa_path).parent
    image_hashes, counts = {}, {name: 0 for name in RENDERERS}
    for item in images:
        require(isinstance(item, dict) and item.get("renderer") in counts and
                isinstance(item.get("sha256"), str) and release.HASH.fullmatch(item["sha256"]) and
                item.get("path") not in image_hashes, "image_evidence_invalid")
        body = read_artifact(relative_artifact(root, item.get("path")), 20 * 1024 * 1024, "qa_image_too_large")
        require(digest(body) == item["sha256"], "rendered_image_changed")
        image_hashes[item["path"]] = item["sha256"]
        counts[item["renderer"]] += 1
    require(all(count == pages for count in counts.values()), "all_page_images_required")
    visual, _ = json_artifact(relative_artifact(root, checks["visual_review"].get("record")),
                              1024 * 1024, "visual_review_too_large")
    rows = visual.get("images")
    require(visual.get("passed") is True and visual.get("pdf_sha256") == plan["preparedSha256"] and
            isinstance(rows, list) and len(rows) == len(image_hashes) and all(isinstance(row, dict) for row in rows) and
            {row.get("path"): row.get("sha256") for row in rows} == image_hashes, "exact_visual_review_required")
    return sha, pages


def checked_bindings(value, pins):
    require(isinstance(value, list) and all(isinstance(row, dict) for row in value), "binding_metadata_invalid")
    rows = copy.deepcopy(value)
    binding_types = release.checked_binding_types(rows)
    by_name = {row["name"]: row for row in rows}
    for name, value in pins.items():
        require(by_name[name].get("text") == value, "expected_dummy_pins_changed")
    # Validate against the existing fixed baseline using a local copy. Never
    # replace module constants: concurrent helpers must retain their own guard.
    baseline = copy.deepcopy(rows)
    for row in baseline:
        if row["name"] in PIN_NAMES:
            row["text"] = release.FIXED_VARS[row["name"]]
    release.checked_bindings(baseline)
    for row in rows:
        if row["type"] == "plain_text":
            require(set(row) == {"name", "type", "text"}, "plain_text_metadata_changed")
        elif row["type"] == "secret_text":
            for key in ("text", "key_base64", "key_jwk"):
                row.pop(key, None)
    return {"bindingsSha256": digest(sorted(rows, key=lambda row: row["name"])),
            "bindingTypes": binding_types,
            "preservedBindingsSha256": digest(sorted((row for row in rows if row["name"] not in PIN_NAMES),
                                                      key=lambda row: row["name"])),
            "plainText": sorted((row for row in rows if row["type"] == "plain_text"), key=lambda row: row["name"])}


def detail(api, version, pins):
    value = api(release.SCRIPT + "/versions/" + version)
    require(isinstance(value, dict) and value.get("id") == version, "version_identity_changed")
    resources = value.get("resources") or {}
    runtime = dict(resources.get("script_runtime") or {})
    require(set(runtime) <= release.RUNTIME_KEYS and runtime.get("migration_tag") == "v1-vault" and
            runtime.get("compatibility_date") == "2026-01-12" and runtime.get("compatibility_flags") == ["nodejs_compat"] and
            runtime.get("usage_model") == "standard", "tested_runtime_changed")
    script = resources.get("script") or {}
    require(isinstance(script.get("etag"), str) and 0 < len(script["etag"]) <= 256, "version_source_etag_required")
    return {**checked_bindings(resources.get("bindings"), pins), "runtime": runtime,
            "sourceEtagSha256": digest(script["etag"].encode()),
            "handlersSha256": digest({"handlers": script.get("handlers"), "namedHandlers": script.get("named_handlers")})}


def source_bytes(api):
    content_type, encoded = api(release.SCRIPT + "/content/v2", raw=True)
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


def snapshot(api, expected_active, expected_latest, active_pins, latest_pins):
    require(release.active(api) == expected_active and release.latest(api) == expected_latest, "version_drift")
    settings = api(release.SCRIPT + "/settings")
    require(isinstance(settings, dict), "settings_metadata_invalid")
    settings_rows = settings.get("bindings")
    # During staging the settings endpoint may describe the old deployed or new
    # uploaded version. Both are checked; no third pin pair is admitted.
    try:
        binding = checked_bindings(settings_rows, latest_pins)
    except SafeFailure as error:
        if str(error) != "expected_dummy_pins_changed" or active_pins == latest_pins:
            raise
        binding = checked_bindings(settings_rows, active_pins)
    stable = {key: item for key, item in settings.items() if key not in ("bindings", "annotations")}
    old, new = detail(api, expected_active, active_pins), detail(api, expected_latest, latest_pins)
    body = source_bytes(api)
    endpoints = release.worker_endpoints(api)
    require(old["preservedBindingsSha256"] == new["preservedBindingsSha256"] == binding["preservedBindingsSha256"],
            "other_bindings_changed")
    require(old["runtime"] == new["runtime"] and old["handlersSha256"] == new["handlersSha256"] and
            old["sourceEtagSha256"] == new["sourceEtagSha256"], "runtime_exports_or_version_source_changed")
    require(release.active(api) == expected_active and release.latest(api) == expected_latest, "state_changed_during_readback")
    return {"activeDetail": old, "latestDetail": new, "settingsSha256": digest(stable),
            "sourceSha256": digest(body), **endpoints}, body


def unchanged(observed, baseline):
    for name in ("sourceSha256", "settingsSha256", "endpointsSha256"):
        require(observed[name] == baseline[name], "source_or_settings_changed")
    for slot in ("activeDetail", "latestDetail"):
        for name in ("preservedBindingsSha256", "runtime", "handlersSha256", "sourceEtagSha256"):
            require(observed[slot][name] == baseline[slot][name], "other_configuration_changed")


def multipart(body, runtime, plain_text, pins, binding_types):
    rows = copy.deepcopy(plain_text)
    for row in rows:
        if row["name"] in PIN_NAMES:
            row["text"] = pins[row["name"]]
    metadata = {"main_module": "worker.js", "bindings": rows,
                "keep_bindings": sorted(set(binding_types) - {"plain_text"}),
                **{key: value for key, value in runtime.items() if key != "migration_tag"}}
    boundary = "kanariya-vault-dummy-" + uuid.uuid4().hex
    parts = []
    for name, mime, value in (("metadata", "application/json", json.dumps(metadata).encode()),
                              ("worker.js", "application/javascript+module", body)):
        filename = '; filename="worker.js"' if name == "worker.js" else ""
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"{filename}\r\n'
                      f'Content-Type: {mime}\r\n\r\n').encode() + value + b"\r\n")
    return b"".join(parts) + f"--{boundary}--\r\n".encode(), boundary


def rotate(api, plan, report, report_path, execute=False):
    old_pins = {"DUMMY_DOCUMENT_ID": plan["currentDocumentId"], "DUMMY_RECORD_SHA256": plan["currentRecordSha256"]}
    new_pins = {"DUMMY_DOCUMENT_ID": plan["id"], "DUMMY_RECORD_SHA256": plan["recordSha256"]}
    report.update(phase="read_only_preflight")
    release.evidence(report_path, report)
    base = release.active(api)
    require(release.latest(api) == base, "active_is_not_latest_upload")
    baseline, body = snapshot(api, base, base, old_pins, old_pins)
    report.update(phase="preflight_verified", baseVersion=base, baseline=baseline)
    release.evidence(report_path, report)
    check_expiry(plan)
    if not execute:
        report.update(status="reviewed_not_executed", phase="dry_run_complete")
        release.evidence(report_path, report)
        return report
    require(report.get("approvalMatched") is True, "exact_plan_approval_required")
    unchanged(snapshot(api, base, base, old_pins, old_pins)[0], baseline)
    check_expiry(plan)
    data, boundary = multipart(body, baseline["latestDetail"]["runtime"], baseline["latestDetail"]["plainText"],
                               new_pins, baseline["latestDetail"]["bindingTypes"])
    report.update(phase="upload_attempt_started", remoteMutations=None)
    release.evidence(report_path, report)
    created = api(release.SCRIPT + "/versions", method="POST", data=data,
                  content_type="multipart/form-data; boundary=" + boundary)
    version = release.version_id(created.get("id"))
    require(version != base, "new_version_not_created")
    report.update(phase="uploaded_not_active", uploadedVersion=version, remoteMutations=1)
    release.evidence(report_path, report)
    unchanged(snapshot(api, base, version, old_pins, new_pins)[0], baseline)
    report.update(phase="uploaded_verified_not_active")
    release.evidence(report_path, report)
    unchanged(snapshot(api, base, version, old_pins, new_pins)[0], baseline)
    check_expiry(plan)
    report.update(phase="activation_attempt_started", remoteMutations=None,
                  sourceOnlyDeployHelperNeedsApprovedPinUpdate=None)
    release.evidence(report_path, report)
    api(release.SCRIPT + "/deployments", method="POST", data={"strategy": "percentage",
        "versions": [{"version_id": version, "percentage": 100}]})
    report.update(phase="activation_acknowledged", remoteMutations=2)
    release.evidence(report_path, report)
    unchanged(snapshot(api, version, version, new_pins, new_pins)[0], baseline)
    report.update(phase="active_dummy_pins_and_configuration_verified", status="passed", percentage=100,
                  twoDummyPinsVerified=True, dummyPinChangesVerified=2, sourceAndOtherBindingsPreserved=True,
                  sourceOnlyDeployHelperNeedsApprovedPinUpdate=True)
    release.evidence(report_path, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--pdf", required=True)
    parser.add_argument("--qa-report", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--approve", help="SHA-256 of the exact owner-reviewed plan file; required for --execute")
    args = parser.parse_args(argv)
    report = {"status": "running_not_verified", "phase": "local_gate", "worker": release.WORKER,
              "executeRequested": args.execute, "remoteMutations": 0, "workerSecretValuesRequested": False,
              "secretBindingsWritten": False, "plannedDummyPinChanges": 2, "dummyPinChangesVerified": 0,
              "r2ApiRequests": 0, "r2ObjectsAccessed": False, "r2ConfigurationWritten": False,
              "r2PublicConfigurationVerified": False, "privateReplacementObjectVerified": False,
              "privateReplacementObjectEvidence": "owner_prepared_manifest_only",
              "notificationsSent": 0, "automaticRetry": False, "automaticRollback": False,
              "serverSideCompareAndSwap": False, "concurrentReleasesMustBePaused": True,
              "sourceOnlyDeployHelperNeedsApprovedPinUpdate": False}
    report_created = False
    try:
        plan, plan_sha = checked_plan(args.plan)
        qa_sha, pages = checked_qa(args.pdf, args.qa_report, plan)
        approval = isinstance(args.approve, str) and release.HASH.fullmatch(args.approve) and args.approve == plan_sha
        require(not args.execute or approval, "exact_plan_approval_required")
        require(not args.approve or approval, "approval_hash_mismatch")
        report.update(planSha256=plan_sha, finalPdfSha256=plan["preparedSha256"], qaSha256=qa_sha,
                      pagesVerified=pages, approvalMatched=bool(approval), replacement=plan)
        release.evidence(args.report, report, create=True)
        report_created = True
        result = rotate(API(), plan, report, args.report, args.execute)
        print(json.dumps({key: result[key] for key in ("status", "phase", "planSha256", "remoteMutations")}, sort_keys=True))
        return 0
    except Exception as error:
        reason = str(error) if isinstance(error, SafeFailure) else "unexpected_error_details_redacted"
        report.update(status="stopped_preserve_state", failedDuringPhase=report["phase"], reason=reason)
        if isinstance(error, SafeFailure) and hasattr(error, "http_status"):
            report.update(httpStatus=error.http_status, apiErrorCodes=error.api_codes, apiResource=error.api_resource)
        if report_created:
            try:
                release.evidence(args.report, report)
            except Exception:
                pass
        print(json.dumps({"status": report["status"], "phase": report["phase"], "reason": reason,
                          "remoteMutations": report["remoteMutations"], "detailsRedacted": True}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
