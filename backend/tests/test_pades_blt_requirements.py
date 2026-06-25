from pathlib import Path


def _minimal_pdf_bytes() -> bytes:
    from io import BytesIO
    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter

    writer = PdfFileWriter()
    contents = writer.add_object(generic.StreamObject(stream_data=b""))
    page = PageObject(
        contents=contents,
        media_box=generic.ArrayObject([
            generic.NumberObject(0),
            generic.NumberObject(0),
            generic.NumberObject(200),
            generic.NumberObject(200),
        ]),
        resources=generic.DictionaryObject(),
    )
    writer.insert_page(page)
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def test_validate_pades_blt_requirements_unsigned_pdf_is_not_blt():
    from app.services.pades_service import validate_pades_blt_requirements

    unsigned_path = Path("data/documents/blt_unsigned_check.pdf")
    unsigned_path.parent.mkdir(parents=True, exist_ok=True)
    unsigned_path.write_bytes(_minimal_pdf_bytes())

    report = validate_pades_blt_requirements(unsigned_path)

    assert report["target_profile"] == "PAdES-B-LT"
    assert report["achieved_profile"] != "PAdES-B-LT"
    assert report["has_embedded_signature"] is False
    assert "embedded PDF signature" in report["missing_requirements"]


def test_validate_pades_blt_requirements_recomputes_missing_requirements():
    from app.services.pades_service import validate_pades_blt_requirements

    unsigned_path = Path("data/documents/blt_recompute_check.pdf")
    unsigned_path.parent.mkdir(parents=True, exist_ok=True)
    unsigned_path.write_bytes(_minimal_pdf_bytes())

    report = validate_pades_blt_requirements(unsigned_path)

    assert report["validation_source"] == "independent_requirement_recomputation"
    assert isinstance(report["missing_requirements"], list)
    assert len(report["missing_requirements"]) >= 1
