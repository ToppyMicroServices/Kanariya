#!/usr/bin/env python3
"""Review and optionally activate one owner-approved final-document manifest.

The default is read-only provider preflight. Execution additionally requires
--approve to equal the SHA-256 of the exact version-2 owner manifest and a
separate manifest-bound owner approval receipt. PDF QA and assistant visual
review evidence must identify the same final bytes and every rendered page.
Approval covers only the two existing document pins, never broad publication.

The existing dummy rotation implementation preserves the source, settings,
other bindings and keys. This helper does not alter its fixed dummy baseline,
read R2 objects or secret values, send notifications, retry, or roll back.
R2 privacy and object contents remain separate checks; this helper cannot
verify them. Provider activation has no documented compare-and-swap.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import unicodedata

_SPEC = importlib.util.spec_from_file_location(
    "kanariya_dummy_rotation", Path(__file__).resolve().with_name("rotate_vault_dummy.py"))
rotation = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rotation)
release = rotation.release
SafeFailure, require, digest = release.SafeFailure, release.require, release.digest
API = release.API
now_ms = rotation.now_ms

MANIFEST_FIELDS = rotation.PLAN_FIELDS | {"recipient", "recipientName"}
ENGINES = ("quartz", "poppler", "pdfjs", "chromium")
REQUIRED_CHECKS = {"final_qpdf", "final_ghostscript", "final_poppler_structure", "fonts",
                   "original_content_preserved", *(name + "_render" for name in ENGINES)}
APPROVAL_FIELDS = {"version", "status", "scope", "approvedAt", "manifestSha256", "finalPdfSha256",
                   "qaReportSha256", "visualReviewSha256", "recipient", "recipientName", "expiresAt",
                   "origin", "bucket", "adminPath", "gateExitCode", "broadPublicationApproved"}
SCOPE = "activate_exact_document_pins_only"
ADMIN_PATH = "/v1/admin"
MAX_PDF = rotation.MAX_PDF
MAX_PAGES = 20
UNSAFE_NAME = re.compile(r'[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\\/:*?"<>|]')
NAME_TRIM = " \t\n\v\f\r\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"


def read_artifact(path, maximum, reason):
    """Bound a regular file read, reject symlinks, and detect replaced bytes."""
    path = release.regular_path(path)
    # Traverse through directory descriptors so a parent replaced by a symlink
    # between validation and opening cannot redirect the read elsewhere.
    directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            next_directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, reason)
        body = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    require(len(body) == before.st_size and
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "artifact_changed_during_read")
    return body


def json_artifact(path, maximum, reason):
    body = read_artifact(path, maximum, reason)
    try:
        value = json.loads(body, object_pairs_hook=rotation.unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(SafeFailure("invalid_json_constant")))
    except (UnicodeError, ValueError):
        raise SafeFailure("artifact_json_invalid") from None
    require(isinstance(value, dict), "artifact_json_object_required")
    return value, digest(body)


def recipient_name(recipient):
    require(isinstance(recipient, dict) and set(recipient) == {"type", "organizationName", "personName"},
            "exact_recipient_required")
    require(recipient["type"] in ("organization", "person"), "recipient_type_invalid")
    org, person = recipient["organizationName"], recipient["personName"]
    require((recipient["type"] == "organization" and isinstance(org, str) and (person is None or isinstance(person, str))) or
            (recipient["type"] == "person" and org is None and isinstance(person, str)), "recipient_fields_invalid")
    parts = []
    for value in (org, person):
        if value is None:
            continue
        try:
            valid = value and value == value.strip(NAME_TRIM) == unicodedata.normalize("NFC", value) and \
                not UNSAFE_NAME.search(value) and len(value.encode("utf-8")) <= 180
        except UnicodeError:
            valid = False
        require(valid, "recipient_name_invalid")
        parts.append(value)
    result = " ".join(parts)
    require(0 < len(result.encode("utf-8")) <= 180, "recipient_name_invalid")
    return result


def checked_manifest(path):
    manifest, sha = json_artifact(path, 16 * 1024, "manifest_too_large")
    require(set(manifest) == MANIFEST_FIELDS and type(manifest.get("version")) is int and
            manifest["version"] == 2 and manifest.get("status") == "prepared_not_active" and
            manifest.get("authMode") == "link", "exact_link_document_manifest_required")
    require(all(isinstance(manifest[key], str) and rotation.UUID4.fullmatch(manifest[key])
                for key in ("id", "currentDocumentId")) and manifest["id"] != manifest["currentDocumentId"],
            "distinct_document_identity_required")
    require(all(isinstance(manifest[key], str) and release.HASH.fullmatch(manifest[key]) for key in
                ("currentRecordSha256", "recordSha256", "preparedSha256", "sourceSha256")) and
            manifest["recordSha256"] != manifest["currentRecordSha256"], "exact_record_hashes_required")
    require(manifest["currentDocumentId"] == release.FIXED_VARS["DUMMY_DOCUMENT_ID"] and
            manifest["currentRecordSha256"] == release.FIXED_VARS["DUMMY_RECORD_SHA256"],
            "approved_current_pins_required")
    require(manifest["recipientName"] == recipient_name(manifest["recipient"]), "recipient_name_mismatch")
    require(type(manifest["watermarkEnabled"]) is bool and rotation.valid_time(manifest["expiresAt"]) and
            rotation.valid_time(manifest["createdAt"]) and manifest["createdAt"] <= now_ms() and
            manifest["createdAt"] < manifest["expiresAt"] and type(manifest["registryRevision"]) is int and
            2 <= manifest["registryRevision"] <= 9007199254740991, "document_policy_invalid")
    require(manifest["expiresAt"] > now_ms(), "replacement_expired")
    return manifest, sha


def qa_artifact(root, value):
    require(isinstance(value, str) and value and "\x00" not in value, "qa_artifact_path_invalid")
    path = Path(value)
    require(all(part not in ("..", ".") for part in path.parts), "qa_artifact_path_invalid")
    path = path if path.is_absolute() else root / path
    require(path.absolute().is_relative_to(root), "qa_artifact_path_invalid")
    return release.regular_path(path)


def clean_output(item):
    value = item.get("output")
    require(isinstance(value, str), "qa_output_required")
    # These are normal qpdf success text, not structural warnings.
    value = re.sub(r"the file may still contain\s+errors that qpdf cannot detect", "", value, flags=re.I)
    value = re.sub(r"no syntax or stream encoding errors found", "", value, flags=re.I)
    value = re.sub(r"\bno warnings\b", "", value, flags=re.I)
    require(not re.search(r"\b(?:warnings?|errors?|repaired|repairing|incorrect\s+xref|recursive\s+dict|cmap|failed)\b",
                          value, re.I), "zero_structural_warnings_required")


def image_rows(rows, root, pages):
    require(isinstance(rows, list) and len(rows) == pages * len(ENGINES), "all_page_images_required")
    indexed, paths = {}, set()
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"engine", "page", "path", "sha256"} and
                isinstance(row.get("engine"), str) and row["engine"] in ENGINES and
                type(row.get("page")) is int and 1 <= row["page"] <= pages and
                isinstance(row.get("sha256"), str) and release.HASH.fullmatch(row["sha256"]),
                "image_evidence_invalid")
        path = qa_artifact(root, row["path"])
        key = (row["engine"], row["page"])
        require(key not in indexed and path not in paths, "duplicate_page_image")
        body = read_artifact(path, 20 * 1024 * 1024, "qa_image_too_large")
        require(digest(body) == row["sha256"], "rendered_image_changed")
        indexed[key] = {"path": str(path), "sha256": row["sha256"]}
        paths.add(path)
    require(set(indexed) == {(engine, page) for engine in ENGINES for page in range(1, pages + 1)},
            "all_page_images_required")
    return indexed


def checked_qa(pdf_path, qa_path, visual_path, manifest):
    pdf_path = release.regular_path(pdf_path)
    pdf = read_artifact(pdf_path, MAX_PDF, "final_pdf_size_invalid")
    require(pdf.startswith(b"%PDF-") and digest(pdf) == manifest["preparedSha256"], "exact_final_pdf_required")
    qa, qa_sha = json_artifact(qa_path, 2 * 1024 * 1024, "qa_report_too_large")
    final = qa.get("final_pdf")
    require(qa.get("status") == "automated_pass" and isinstance(final, dict) and
            final.get("path") == str(pdf_path) and final.get("sha256") == manifest["preparedSha256"] and
            type(final.get("size_bytes")) is int and final["size_bytes"] == len(pdf) and
            type(final.get("pages")) is int and 1 <= final["pages"] <= MAX_PAGES,
            "exact_final_pdf_qa_required")
    require(qa.get("warnings", []) == [], "zero_structural_warnings_required")
    pages = final["pages"]
    checks = qa.get("checks")
    require(isinstance(checks, dict) and REQUIRED_CHECKS <= set(checks) and
            all(isinstance(item, dict) and item.get("status") == "pass" for item in checks.values()),
            "all_qa_checks_must_pass")
    versions = qa.get("tool_versions")
    required_versions = ("qpdf", "ghostscript", *(engine for engine in ENGINES if engine != "quartz"))
    require(isinstance(versions, dict) and all(isinstance(versions.get(name), str) and
            versions[name].strip() for name in required_versions) and
            any(isinstance(versions.get(name), str) and versions[name].strip()
                for name in ("quartz", "macos_quartz_os")), "renderer_versions_required")
    for item in checks.values():
        for field in ("warnings", "structural_warnings"):
            require(field not in item or item[field] == [], "zero_structural_warnings_required")
        if "exit_code" in item:
            require(type(item["exit_code"]) is int and item["exit_code"] == 0, "qa_exit_code_must_be_zero")
    for name in ("final_qpdf", "final_ghostscript"):
        require(type(checks[name].get("exit_code")) is int and checks[name]["exit_code"] == 0,
                "qa_exit_code_must_be_zero")
    for name in ("final_qpdf", "final_ghostscript", "final_poppler_structure"):
        clean_output(checks[name])
    for engine in ENGINES:
        item = checks[engine + "_render"]
        require(type(item.get("pages")) is int and item["pages"] == pages, "all_page_render_checks_required")
        clean_output(item)
    root = release.regular_path(qa_path).parent
    artifacts = qa.get("qa_artifacts")
    require(isinstance(artifacts, dict), "qa_artifact_evidence_required")
    images = image_rows(artifacts.get("images"), root, pages)
    if "preview" in artifacts or "preview_sha256" in artifacts:
        require(isinstance(artifacts.get("preview_sha256"), str) and
                release.HASH.fullmatch(artifacts["preview_sha256"]), "qa_preview_evidence_invalid")
        preview = read_artifact(qa_artifact(root, artifacts.get("preview")), 20 * 1024 * 1024,
                                "qa_preview_too_large")
        require(digest(preview) == artifacts["preview_sha256"], "qa_preview_changed")
    visual, visual_sha = json_artifact(visual_path, 1024 * 1024, "visual_review_too_large")
    require(visual.get("status") == "assistant_visual_review_passed" and
            visual.get("pdf_sha256") == manifest["preparedSha256"] and visual.get("qa_report_sha256") == qa_sha,
            "exact_assistant_visual_review_required")
    require(image_rows(visual.get("images"), root, pages) == images, "exact_visual_images_required")
    return qa_sha, visual_sha, pages


def checked_owner_approval(path, manifest, manifest_sha, qa_sha, visual_sha):
    require(path is not None, "owner_approval_record_required")
    approval, sha = json_artifact(path, 16 * 1024, "owner_approval_too_large")
    require(set(approval) == APPROVAL_FIELDS and type(approval.get("version")) is int and approval["version"] == 1 and
            approval.get("status") == "approved_exact_document_activation" and approval.get("scope") == SCOPE and
            approval.get("origin") == release.FIXED_VARS["PUBLIC_ORIGIN"] and approval.get("bucket") == release.BUCKET and
            approval.get("adminPath") == ADMIN_PATH and approval.get("broadPublicationApproved") is False,
            "exact_owner_scope_required")
    require(approval.get("manifestSha256") == manifest_sha and
            approval.get("finalPdfSha256") == manifest["preparedSha256"] and approval.get("qaReportSha256") == qa_sha and
            approval.get("visualReviewSha256") == visual_sha, "owner_approval_hash_mismatch")
    require(approval.get("recipient") == manifest["recipient"] and
            approval.get("recipientName") == manifest["recipientName"] and
            type(approval.get("expiresAt")) is int and approval["expiresAt"] == manifest["expiresAt"],
            "owner_approval_document_mismatch")
    require(rotation.valid_time(approval.get("approvedAt")) and manifest["createdAt"] <= approval["approvedAt"] <= now_ms() and
            type(approval.get("gateExitCode")) is int and approval["gateExitCode"] == 0,
            "owner_approval_gate_required")
    return sha


def local_gate(args):
    manifest, manifest_sha = checked_manifest(args.manifest)
    qa_sha, visual_sha, pages = checked_qa(args.pdf, args.qa_report, args.visual_review, manifest)
    owner_sha = checked_owner_approval(args.owner_approval, manifest, manifest_sha, qa_sha, visual_sha)
    return manifest, {"manifestSha256": manifest_sha, "finalPdfSha256": manifest["preparedSha256"],
                      "qaReportSha256": qa_sha, "visualReviewSha256": visual_sha,
                      "ownerApprovalSha256": owner_sha, "pagesVerified": pages}


def rotate_document(api, manifest, report, report_path, execute=False, artifact_gate=None):
    mutations_sent = 0

    def guarded_api(path, method="GET", **kwargs):
        nonlocal mutations_sent
        if method != "GET":
            require(artifact_gate is not None, "local_artifact_recheck_required")
            try:
                artifact_gate()
            except Exception:
                report.update(remoteMutations=mutations_sent,
                              phase="local_artifact_recheck_failed_before_" + ("upload" if mutations_sent == 0 else "activation"),
                              sourceOnlyDeployHelperNeedsApprovedPinUpdate=False)
                raise
            mutations_sent += 1
        return api(path, method=method, **kwargs)

    result = rotation.rotate(guarded_api, manifest, report, report_path, execute)
    if execute:
        result.update(phase="active_document_pins_and_configuration_verified", exactDocumentPinsVerified=True)
        release.evidence(report_path, result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--pdf", required=True)
    parser.add_argument("--qa-report", required=True)
    parser.add_argument("--visual-review", required=True)
    parser.add_argument("--owner-approval")
    parser.add_argument("--report", required=True, help="New private operation report path; created with mode 0600")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--approve", help="SHA-256 of the exact version-2 owner manifest; required for execution")
    args = parser.parse_args(argv)
    report = {"status": "running_not_verified", "phase": "local_gate", "worker": release.WORKER,
              "executeRequested": args.execute, "remoteMutations": 0, "plannedDocumentPinChanges": 2,
              "exactDocumentPinsVerified": False, "workerSecretValuesRequested": False, "secretBindingsWritten": False,
              "r2ApiRequests": 0, "r2ObjectsAccessed": False, "r2ConfigurationWritten": False,
              "r2PublicConfigurationVerified": False, "privateReplacementObjectVerified": False,
              "privateReplacementObjectEvidence": "owner_manifest_only_not_independently_verified",
              "ownerApprovalRecordMatched": False, "assistantVisualReviewRecordMatched": False,
              "userConfirmationEvidence": "owner_approval_record_only", "broadPublicationApproved": False,
              "notificationsSent": 0, "automaticRetry": False, "automaticRollback": False,
              "serverSideCompareAndSwap": False, "concurrentReleasesMustBePaused": True,
              "sourceOnlyDeployHelperNeedsApprovedPinUpdate": False}
    report_created = False
    try:
        manifest, evidence = local_gate(args)
        approval = isinstance(args.approve, str) and release.HASH.fullmatch(args.approve) and \
            args.approve == evidence["manifestSha256"]
        require(not args.execute or approval, "exact_manifest_approval_required")
        require(not args.approve or approval, "approval_hash_mismatch")
        report.update(**evidence, approvalMatched=bool(approval), ownerApprovalRecordMatched=True,
                      assistantVisualReviewRecordMatched=True, automatedQaRecordMatched=True,
                      ownerScope=SCOPE, origin=release.FIXED_VARS["PUBLIC_ORIGIN"], bucket=release.BUCKET,
                      adminPath=ADMIN_PATH)
        release.evidence(args.report, report, create=True)
        report_created = True

        def recheck():
            fresh_manifest, fresh_evidence = local_gate(args)
            require(fresh_manifest == manifest and fresh_evidence == evidence, "approved_artifacts_changed")

        result = rotate_document(API(), manifest, report, args.report, args.execute, recheck)
        print(json.dumps({key: result[key] for key in ("status", "phase", "manifestSha256", "remoteMutations")}, sort_keys=True))
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
