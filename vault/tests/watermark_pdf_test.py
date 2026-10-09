"""Owner-side in-memory stamping tests; no real CV or credential fixtures."""
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

from pypdf import PdfReader, PdfWriter
from pypdf.generic import ArrayObject, DictionaryObject, NameObject, RectangleObject, TextStringObject
from reportlab.pdfgen import canvas

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "watermark-pdf.py"
spec = importlib.util.spec_from_file_location("watermark_pdf", SCRIPT)
watermark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watermark)
FONT = os.environ.get("KANARIYA_TEST_FONT", "/System/Library/Fonts/Supplemental/Arial Unicode.ttf")


def fixture(pages=1):
    data = io.BytesIO()
    document = canvas.Canvas(data, pagesize=(595, 842), invariant=1)
    for index in range(pages):
        document.drawString(60, 730, f"SYNTHETIC PAGE {index + 1}")
        document.showPage()
    document.save()
    return data.getvalue()


def edited_pdf(edit):
    writer = PdfWriter()
    writer.clone_document_from_reader(PdfReader(io.BytesIO(fixture(3))))
    edit(writer)
    data = io.BytesIO()
    writer.write(data)
    return data.getvalue()


@unittest.skipUnless(Path(FONT).is_file(), "Set KANARIYA_TEST_FONT to a Japanese TrueType font")
class WatermarkTest(unittest.TestCase):
    def test_each_page_keeps_original_text_boxes_and_rotation(self):
        def edit(writer):
            writer.pages[1].rotate(90)
            writer.pages[2].mediabox = RectangleObject((20, 30, 615, 872))
            writer.pages[2].cropbox = RectangleObject((45, 70, 565, 802))
            writer.pages[2].rotate(270)
        source = edited_pdf(edit)
        result = watermark.watermark_pdf(source, "株式会社サンプル 山田太郎", FONT)
        before, after = PdfReader(io.BytesIO(source)), PdfReader(io.BytesIO(result))
        self.assertEqual(len(after.pages), 3)
        self.assertGreaterEqual(after.pdf_header, "%PDF-1.4")
        for index, (original, stamped) in enumerate(zip(before.pages, after.pages)):
            self.assertEqual(list(original.mediabox), list(stamped.mediabox))
            self.assertEqual(list(original.cropbox), list(stamped.cropbox))
            self.assertEqual(original.rotation, stamped.rotation)
            self.assertIn(f"SYNTHETIC PAGE {index + 1}", stamped.extract_text())
            self.assertIn("開示先: 株式会社サンプル 山田太郎", stamped.extract_text())
            states = stamped["/Resources"]["/ExtGState"].values()
            self.assertTrue(any(float(state.get_object().get("/ca", 1)) == .2 for state in states))
            self.assertFalse(stamped.get("/Annots"))
            self.assertTrue(any(font.get_object().get("/FontDescriptor", {}).get_object().get("/FontFile2")
                                for font in stamped["/Resources"]["/Font"].values()
                                if font.get_object().get("/FontDescriptor")))
            for font in stamped["/Resources"]["/Font"].values():
                mapping = font.get_object().get("/ToUnicode")
                if mapping:
                    # Regression: Ghostscript warned on ReportLab's >100-entry groups.
                    groups = re.findall(rb"(\d+) beginbfchar", mapping.get_object().get_data())
                    self.assertTrue(groups and all(int(count) <= 100 for count in groups))

    def test_reject_encrypted_and_interactive_input(self):
        for edit in [lambda w: w.encrypt("synthetic-only"),
                     lambda w: w._root_object.update({NameObject("/AcroForm"): DictionaryObject()}),
                     lambda w: w._root_object.update({NameObject("/Perms"): DictionaryObject({NameObject("/DocMDP"): DictionaryObject({NameObject("/Type"): NameObject("/Sig")})})}),
                     lambda w: w._root_object.update({NameObject("/OpenAction"): ArrayObject()}),
                     lambda w: w.pages[0].update({NameObject("/Annots"): ArrayObject([DictionaryObject({NameObject('/Subtype'): NameObject('/Widget')})])})]:
            with self.subTest(edit=edit), self.assertRaises(Exception):
                watermark.watermark_pdf(edited_pdf(edit), "動作確認用", FONT)

    def test_recipient_validation_and_unavailable_glyph(self):
        for name in ["", " \t ", "a/b", "a\\b", "a:b", "a\u202eb", "a\u2028b", "a\x00b", "あ" * 61, "a\ud800b", "name\n", "\nname"]:
            with self.subTest(name=repr(name)), self.assertRaises(Exception):
                watermark.watermark_pdf(fixture(), name, FONT)
        with self.assertRaises(ValueError):
            watermark.watermark_pdf(fixture(), "試験\U0001f9d1", FONT)
        self.assertEqual(watermark.recipient_name("  株式会社サンプル  "), "株式会社サンプル")

    def test_preserve_benign_links_and_reject_unsafe_actions(self):
        for uri in ["https://example.invalid/cv", "mailto:test@example.invalid", "javascript:alert(1)", "http://example.invalid/cv"]:
            def edit(writer):
                annotation = DictionaryObject({NameObject("/Type"): NameObject("/Annot"), NameObject("/Subtype"): NameObject("/Link"),
                    NameObject("/Rect"): RectangleObject((50, 50, 150, 70)),
                    NameObject("/A"): DictionaryObject({NameObject("/S"): NameObject("/URI"), NameObject("/URI"): TextStringObject(uri)})})
                writer.pages[0][NameObject("/Annots")] = ArrayObject([writer._add_object(annotation)])
            source = edited_pdf(edit)
            if uri.startswith(("https:", "mailto:")):
                result = watermark.watermark_pdf(source, "動作確認用", FONT)
                annotation = PdfReader(io.BytesIO(result)).pages[0]["/Annots"][0].get_object()
                self.assertEqual(annotation["/A"]["/URI"], uri)
                self.assertEqual(list(annotation["/Rect"]), [50, 50, 150, 70])
            else:
                with self.assertRaises(ValueError):
                    watermark.watermark_pdf(source, "動作確認用", FONT)

    def test_reject_more_than_viewer_page_limit(self):
        with self.assertRaises(ValueError):
            watermark.watermark_pdf(fixture(21), "動作確認用", FONT)

    def test_cli_has_only_pdf_output_and_generic_failure(self):
        request = {"pdfBase64": base64.b64encode(fixture()).decode(), "recipientName": "動作確認用", "fontPath": FONT}
        result = subprocess.run([sys.executable, str(SCRIPT)], input=json.dumps(request).encode(), capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertTrue(result.stdout.startswith(b"%PDF-"))
        request["recipientName"] = "private/recipient"
        result = subprocess.run([sys.executable, str(SCRIPT)], input=json.dumps(request).encode(), capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b'{"status":"failed","code":"watermark_failed"}\n')

    def test_reject_oversized_and_malformed_input(self):
        for pdf in [b"not-pdf", b"%PDF-1.7 malformed", b"%PDF-" + b"x" * watermark.MAX_PDF_BYTES]:
            with self.subTest(size=len(pdf)), self.assertRaises(Exception):
                watermark.watermark_pdf(pdf, "動作確認用", FONT)


if __name__ == "__main__":
    unittest.main()
