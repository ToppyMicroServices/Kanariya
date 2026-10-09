#!/usr/bin/env python3
"""Stamp owner-supplied recipient text in memory; stdout contains PDF bytes only.

Dependencies: pypdf and reportlab. Supply a locally licensed TrueType font with
all recipient glyphs. Fonts, names, document bytes and keys are never logged.
"""
import base64
import contextlib
import io
import json
import logging
import math
from pathlib import Path
import re
import sys
import unicodedata
import warnings

MAX_PDF_BYTES = 1024 * 1024
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_PAGES = 20
WATERMARK_ALPHA = 0.20
WATERMARK_GRAY = 0.45


def recipient_name(value):
    if not isinstance(value, str):
        raise ValueError("invalid_recipient")
    if re.search(r'[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069/\\:*?"<>|]', value):
        raise ValueError("invalid_recipient")
    value = unicodedata.normalize("NFC", value.strip().strip("\ufeff").strip())
    if not value or len(value.encode("utf-8")) > 180:
        raise ValueError("invalid_recipient")
    return value


def _reject_interactive(reader):
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject
    forbidden = {"/AcroForm", "/OpenAction", "/AA", "/JS", "/JavaScript",
                 "/EmbeddedFiles", "/XFA", "/RichMedia", "/Launch", "/SubmitForm", "/ImportData"}
    actions = {"/JavaScript", "/Launch", "/GoToR", "/GoToE", "/SubmitForm",
               "/ImportData", "/Rendition", "/Sound", "/Movie", "/URL"}

    def link_action(action):
        from urllib.parse import urlsplit
        action = action.get_object()
        if not isinstance(action, DictionaryObject) or "/Next" in action:
            raise ValueError("unsupported_pdf")
        if action.get("/S") == "/GoTo" and action.get("/D") is not None:
            return
        if action.get("/S") == "/URI":
            uri = action.get("/URI")
            if isinstance(uri, str) and not re.search(r"[\x00-\x20\x7f-\x9f]", uri):
                parsed = urlsplit(uri)
                if (parsed.scheme == "https" and parsed.netloc) or (parsed.scheme == "mailto" and parsed.path):
                    return
        raise ValueError("unsupported_pdf")

    for page in reader.pages:
        annotations = page.get("/Annots")
        for ref in annotations.get_object() if annotations is not None else []:
            annotation = ref.get_object()
            if annotation.get("/Subtype") != "/Link" or not ("/A" in annotation or "/Dest" in annotation):
                raise ValueError("unsupported_pdf")
            if "/A" in annotation:
                link_action(annotation["/A"])

    def walk(value, depth=0):
        if depth > 100:
            raise ValueError("unsupported_pdf")
        if isinstance(value, IndirectObject):
            return
        if isinstance(value, DictionaryObject):
            if (forbidden.intersection(value) or value.get("/Type") in {"/Sig", "/Filespec"}
                    or value.get("/FT") == "/Sig" or value.get("/Subtype") == "/Widget"):
                raise ValueError("unsupported_pdf")
            if value.get("/S") in actions:
                raise ValueError("unsupported_pdf")
            if "/A" in value:
                link_action(value["/A"])
            if value.get("/S") == "/URI" or value.get("/Type") == "/Action":
                link_action(value)
            for item in value.values():
                walk(item, depth + 1)
        elif isinstance(value, ArrayObject):
            for item in value:
                walk(item, depth + 1)

    refs = {(int(number), int(generation)) for generation, group in reader.xref.items()
            for number in group if number != 0}
    refs |= {(int(number), 0) for number in reader.xref_objStm}
    for number, generation in refs:
        walk(IndirectObject(number, generation, reader).get_object())


def _normalize_overlay_cmaps(page):
    # ReportLab 4.4 emits one large bfchar group. Ghostscript rejects groups
    # above 100 entries; split only this newly generated overlay's maps.
    for font in page["/Resources"]["/Font"].values():
        mapping = font.get_object().get("/ToUnicode")
        if mapping is None:
            continue
        stream = mapping.get_object()
        data = stream.get_data()

        def split_group(match):
            rows = [row for row in match[2].splitlines() if row.strip()]
            if len(rows) != int(match[1]):
                raise ValueError("invalid_generated_font")
            return b"\n".join(str(len(rows[start:start + 100])).encode() + b" beginbfchar\n" +
                               b"\n".join(rows[start:start + 100]) + b"\nendbfchar"
                               for start in range(0, len(rows), 100))
        stream.set_data(re.sub(rb"(\d+) beginbfchar\s*\n(.*?)\nendbfchar", split_group, data, flags=re.DOTALL))


def watermark_pdf(pdf_bytes, name, font_path):
    """Return PDF content with an embedded gray recipient mark on every page.

    Original page boxes/rotation, text and benign links remain intact. Forms,
    signed, encrypted, active or malformed PDFs fail closed instead of flattening.
    """
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import RectangleObject
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfgen import canvas

    name = recipient_name(name)
    if (not isinstance(pdf_bytes, bytes) or not 5 <= len(pdf_bytes) <= MAX_PDF_BYTES
            or not pdf_bytes.startswith(b"%PDF-")):
        raise ValueError("invalid_pdf")
    if not isinstance(font_path, str) or not font_path or len(font_path) > 4096:
        raise ValueError("invalid_font")
    path = Path(font_path)
    if not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("invalid_font")
    logger = logging.getLogger("pypdf")
    diagnostics = []

    class Capture(logging.Handler):
        def emit(self, record):
            diagnostics.append(record.levelno)

    handler = Capture(logging.WARNING)
    previous_propagate = logger.propagate
    logger.addHandler(handler)
    logger.propagate = False
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            font = TTFont("KanariyaRecipient", str(path))
            label = "開示先: " + name
            if any(ord(char) not in font.face.charToGlyph for char in label):
                raise ValueError("unsupported_glyph")
            pdfmetrics.registerFont(font)
            reader = PdfReader(io.BytesIO(pdf_bytes), strict=True)
            if reader.is_encrypted or not 1 <= len(reader.pages) <= MAX_PAGES:
                raise ValueError("unsupported_pdf")
            _reject_interactive(reader)
            writer = PdfWriter()
            writer.clone_document_from_reader(reader)
            if writer.pdf_header < "%PDF-1.4":
                writer.pdf_header = "%PDF-1.4"
            for page in writer.pages:
                media, crop = list(map(float, page.mediabox)), list(map(float, page.cropbox))
                rotation = page.rotation
                if (rotation % 90 or any(not math.isfinite(n) for n in media + crop)
                        or media[2] <= media[0] or media[3] <= media[1]
                        or crop[2] <= crop[0] or crop[3] <= crop[1]
                        or max(abs(n) for n in media + crop) > 20000):
                    raise ValueError("unsupported_page")
                if (crop[0] < media[0] or crop[1] < media[1]
                        or crop[2] > media[2] or crop[3] > media[3]):
                    raise ValueError("unsupported_page")
                width, height = crop[2] - crop[0], crop[3] - crop[1]
                visible_width, visible_height = (height, width) if rotation % 180 else (width, height)
                angle = math.radians(35)
                span = min(visible_width / math.cos(angle), visible_height / math.sin(angle)) * .80
                size = min(42, span / pdfmetrics.stringWidth(label, "KanariyaRecipient", 1))
                if size < 12:
                    raise ValueError("recipient_too_long_for_page")
                overlay = io.BytesIO()
                drawing = canvas.Canvas(overlay, pagesize=(media[2] - media[0], media[3] - media[1]),
                                        pageCompression=1, invariant=1)
                drawing.setFillGray(WATERMARK_GRAY)
                drawing.setFillAlpha(WATERMARK_ALPHA)
                drawing.translate((crop[0] + crop[2]) / 2, (crop[1] + crop[3]) / 2)
                drawing.rotate(35 + rotation)
                drawing.setFont("KanariyaRecipient", size)
                drawing.drawCentredString(0, -size * .3, label)
                drawing.showPage()
                drawing.save()
                overlay_page = PdfReader(io.BytesIO(overlay.getvalue()), strict=True).pages[0]
                overlay_page.mediabox = RectangleObject(media)
                overlay_page.cropbox = RectangleObject(crop)
                _normalize_overlay_cmaps(overlay_page)
                page.merge_page(overlay_page, over=True, expand=False)
            output = io.BytesIO()
            writer.write(output)
            result = output.getvalue()
            if diagnostics or len(result) > MAX_PDF_BYTES:
                raise ValueError("invalid_watermarked_pdf")
            return result
    finally:
        logger.removeHandler(handler)
        logger.propagate = previous_propagate


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError()
        request = json.loads(raw)
        if not isinstance(request, dict) or set(request) != {"pdfBase64", "recipientName", "fontPath"}:
            raise ValueError()
        pdf = base64.b64decode(request["pdfBase64"], validate=True)
        diagnostics = io.StringIO()
        with contextlib.redirect_stdout(diagnostics), contextlib.redirect_stderr(diagnostics):
            output = watermark_pdf(pdf, request["recipientName"], request["fontPath"])
        if diagnostics.getvalue():
            raise ValueError()
        sys.stdout.buffer.write(output)
    except Exception:
        sys.stderr.write('{"status":"failed","code":"watermark_failed"}\n')
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
