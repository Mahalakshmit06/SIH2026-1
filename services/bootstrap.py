"""First-launch provisioning for the SECURE TEST & AUDIT DASHBOARD node.

Generates a realistic captured field-evidence photograph for every initial
test record (lateral-flow cassette on a color-reference card) and seeds the
secure store the first time the node runs.
"""

from __future__ import annotations

import random
from datetime import datetime
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont, ImageOps

from services import audit, database, integrity

# Reference swatches used on every evidence card.
REFERENCE_SWATCHES = [
    (94, 138, 100),    # green
    (203, 170, 52),    # yellow
    (208, 122, 47),    # orange
    (176, 68, 62),     # red
    (122, 90, 160),    # purple
    (46, 125, 140),    # teal
    (138, 58, 92),     # maroon
    (112, 122, 62),    # olive
    (179, 80, 110),    # rose
    (59, 111, 176),    # blue
]

_COLOR_BY_ID = {
    "NCB-20260919-001": (176, 68, 62),
    "NCB-20260919-002": (203, 170, 52),
    "NCB-20260919-003": (208, 122, 47),
    "NCB-20260919-004": (176, 68, 62),
    "NCB-20260919-005": (122, 90, 160),
    "NCB-20260919-006": (46, 125, 140),
    "NCB-20260919-007": (138, 58, 92),
    "NCB-20260919-008": (112, 122, 62),
    "NCB-20260919-009": (179, 80, 110),
    "NCB-20260919-010": (59, 111, 176),
}

_SAMPLES = [
    {
        "test_id": "NCB-20260919-001",
        "timestamp": "2026-09-19 09:04:12",
        "classification": "POSITIVE",
        "source": "MOBILE_EDGE_NODE_7742",
        "area": "Chennai Central",
        "district": "Chennai",
        "latitude": 13.0827,
        "longitude": 80.2707,
        "officer_id": "OFFICER-7742",
        "notes": "Sample flagged during routine screening at the central-zone checkpoint.",
    },
    {
        "test_id": "NCB-20260919-002",
        "timestamp": "2026-09-19 09:41:53",
        "classification": "POSITIVE",
        "source": "MOBILE_EDGE_NODE_7742",
        "area": "Chennai North",
        "district": "Chennai",
        "latitude": 13.1132,
        "longitude": 80.2918,
        "officer_id": "OFFICER-7714",
        "notes": "Flagged for confirmatory laboratory analysis.",
    },
    {
        "test_id": "NCB-20260919-003",
        "timestamp": "2026-09-19 10:17:26",
        "classification": "POSITIVE",
        "source": "MOBILE_EDGE_NODE_7742",
        "area": "Chennai South",
        "district": "Chennai",
        "latitude": 12.9771,
        "longitude": 80.2304,
        "officer_id": "OFFICER-7757",
        "notes": "Subject under observation; escalated to the district response cell.",
    },
    {
        "test_id": "NCB-20260919-004",
        "timestamp": "2026-09-19 10:44:05",
        "classification": "POSITIVE",
        "source": "MOBILE_EDGE_NODE_7742",
        "area": "Chennai Central",
        "district": "Chennai",
        "latitude": 13.0619,
        "longitude": 80.2501,
        "officer_id": "OFFICER-7742",
        "notes": "Sample matched to reference swatch; escalated for confirmation.",
    },
    {
        "test_id": "NCB-20260919-005",
        "timestamp": "2026-09-19 11:12:47",
        "classification": "INCONCLUSIVE",
        "source": "MOBILE_EDGE_NODE_7742",
        "area": "Tiruvallur",
        "district": "Tiruvallur",
        "latitude": 13.1436,
        "longitude": 79.9089,
        "officer_id": "OFFICER-7703",
        "notes": "Line intensity near threshold; resampling recommended.",
    },
    {
        "test_id": "NCB-20260919-006",
        "timestamp": "2026-09-19 09:15:00",
        "classification": "NEGATIVE",
        "source": "MOBILE_EDGE_NODE_7742",
        "area": "Chennai South",
        "district": "Chennai",
        "latitude": 13.0587,
        "longitude": 80.2494,
        "officer_id": "OFFICER-7729",
        "notes": "Routine check recorded with colorimetric reference comparison.",
    },
    {
        "test_id": "NCB-20260919-007",
        "timestamp": "2026-09-19 11:48:31",
        "classification": "NEGATIVE",
        "source": "MOBILE_EDGE_NODE_7742",
        "area": "Chennai North",
        "district": "Chennai",
        "latitude": 13.0964,
        "longitude": 80.2889,
        "officer_id": "OFFICER-7714",
        "notes": "Clean result; evidence stored on file.",
    },
    {
        "test_id": "NCB-20260919-008",
        "timestamp": "2026-09-19 12:21:09",
        "classification": "INCONCLUSIVE",
        "source": "MOBILE_EDGE_NODE_7742",
        "area": "Chengalpattu",
        "district": "Chengalpattu",
        "latitude": 12.6944,
        "longitude": 79.988,
        "officer_id": "OFFICER-7736",
        "notes": "Weak signal detected; verification pass requested.",
    },
    {
        "test_id": "NCB-20260919-009",
        "timestamp": "2026-09-19 12:55:38",
        "classification": "POSITIVE",
        "source": "MOBILE_EDGE_NODE_7742",
        "area": "Kancheepuram",
        "district": "Kancheepuram",
        "latitude": 12.8387,
        "longitude": 79.7014,
        "officer_id": "OFFICER-7730",
        "notes": "Positive detection logged during the scheduled district sweep.",
    },
    {
        "test_id": "NCB-20260919-010",
        "timestamp": "2026-09-19 13:32:04",
        "classification": "POSITIVE",
        "source": "MOBILE_EDGE_NODE_7742",
        "area": "Chennai South",
        "district": "Chennai",
        "latitude": 12.9795,
        "longitude": 80.2331,
        "officer_id": "OFFICER-7757",
        "notes": "Confirmed positive; chain of custody forwarded with evidence.",
    },
]


# ---------------------------------------------------------------------------
# Evidence image generator
# ---------------------------------------------------------------------------

def _load_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    names = ["arialbd.ttf", "arial.ttf"] if bold else ["arial.ttf", "arialbd.ttf"]
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _make_evidence(path: Path, result_color: tuple, serial: str, seed: int) -> None:
    rng = random.Random(seed)
    width, height = 840, 580

    base = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(base)

    # Warm desk surface with a soft vertical light gradient.
    top = (222, 214, 200)
    bottom = (178, 164, 148)
    for y in range(height):
        t = y / (height - 1)
        tone = tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3))
        draw.line([(0, y), (width, y)], fill=(tone[0], tone[1], tone[2], 255))

    # Mottled surface texture.
    texture = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    td = ImageDraw.Draw(texture)
    for _ in range(70):
        x = rng.randint(0, width)
        y = rng.randint(0, height)
        r = rng.randint(40, 170)
        shade = rng.choice([(255, 255, 255, 10), (0, 0, 0, 10), (0, 0, 0, 6)])
        td.ellipse([x - r, y - r, x + r, y + r], fill=shade)
    base.alpha_composite(texture)

    card_w, card_h = 680, 440
    x0 = (width - card_w) // 2
    y0 = (height - card_h) // 2 + 4

    # Card stack (shadow + card + stamp) built separately and then rotated.
    stack = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    sd = ImageDraw.Draw(stack)
    sd.rounded_rectangle(
        [x0 + 9, y0 + 18, x0 + card_w + 9, y0 + card_h + 18],
        radius=20, fill=(52, 44, 34, 90),
    )

    card = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    cd = ImageDraw.Draw(card)
    cd.rounded_rectangle(
        [x0, y0, x0 + card_w, y0 + card_h], radius=14,
        fill=(250, 247, 241, 255), outline=(148, 139, 126, 255), width=3,
    )

    # Card header.
    cd.text(
        (x0 + 32, y0 + 24),
        "CAUTION: HANDLE AS EVIDENCE",
        font=_load_font(15), fill=(150, 110, 90, 255),
    )
    ref = f"REF {serial}"
    cd.text(
        (x0 + card_w - 32 - cd.textlength(ref, font=_load_font(15)), y0 + 24),
        ref, font=_load_font(15), fill=(96, 88, 78, 255),
    )
    cd.line([x0 + 32, y0 + 56, x0 + card_w - 32, y0 + 56], fill=(216, 208, 196, 255), width=1)

    # Reference swatch row.
    sw, gap = 46, 12
    row_width = len(REFERENCE_SWATCHES) * sw + (len(REFERENCE_SWATCHES) - 1) * gap
    sx = x0 + (card_w - row_width) // 2
    sy = y0 + 82
    for index, color in enumerate(REFERENCE_SWATCHES):
        left = sx + index * (sw + gap)
        cd.rounded_rectangle(
            [left, sy, left + sw, sy + sw], radius=7,
            fill=color + (255,), outline=(176, 166, 152, 255), width=1,
        )
        if color == tuple(result_color):
            cd.rounded_rectangle(
                [left - 4, sy - 4, left + sw + 4, sy + sw + 4],
                radius=10, outline=(204, 138, 60, 255), width=3,
            )
    cd.text(
        (x0 + 32, sy + sw + 12),
        "MATCH SAMPLE LINE TO THE NEAREST REFERENCE SWATCH",
        font=_load_font(12), fill=(128, 118, 104, 255),
    )

    # Lateral-flow test cassette.
    sx1, sy1 = x0 + 60, y0 + 196
    sw_x, sw_y = 560, 150
    cd.rounded_rectangle(
        [sx1, sy1, sx1 + sw_x, sy1 + sw_y], radius=10,
        fill=(247, 244, 239, 255), outline=(168, 160, 148, 255), width=2,
    )
    cd.text((sx1 + 20, sy1 + 12), "LFA TEST CASSETTE", font=_load_font(13), fill=(110, 102, 92, 255))

    membrane_left = sx1 + 120
    membrane_top = sy1 + 56
    membrane_w = sw_x - 240
    membrane_h = 56
    cd.rectangle(
        [membrane_left, membrane_top, membrane_left + membrane_w, membrane_top + membrane_h],
        fill=(240, 237, 231, 255), outline=(206, 200, 190, 255), width=1,
    )
    cd.rectangle(
        [sx1 + 20, membrane_top + 6, sx1 + 118, membrane_top + membrane_h - 6],
        fill=(214, 209, 200, 255),
    )

    line_y = membrane_top + membrane_h // 2
    test_x = membrane_left + int(membrane_w * 0.28)
    test_w = int(membrane_w * 0.13)
    cd.rectangle([test_x, line_y - 4, test_x + test_w, line_y + 4], fill=result_color + (255,))

    control_x = membrane_left + int(membrane_w * 0.62)
    control_w = int(membrane_w * 0.13)
    cd.rectangle([control_x, line_y - 4, control_x + control_w, line_y + 4], fill=(76, 76, 76, 255))

    cd.text((test_x + test_w // 2 - 4, line_y + 12), "T", font=_load_font(11), fill=(110, 102, 92, 255))
    cd.text((control_x + control_w // 2 - 4, line_y + 12), "C", font=_load_font(11), fill=(110, 102, 92, 255))

    # Sample label and barcode along the bottom of the card.
    cd.text((x0 + 60, y0 + 390), f"SAMPLE {serial}", font=_load_font(17, bold=True), fill=(64, 56, 46, 255))
    barcode = Image.new("RGBA", (120, 34), (0, 0, 0, 0))
    bd = ImageDraw.Draw(barcode)
    bx = 0
    while bx < 120:
        bar_w = rng.randint(1, 3)
        bd.rectangle([bx, 0, bx + bar_w, 34], fill=(64, 56, 46, 255))
        bx += bar_w + rng.randint(1, 3)
    card.alpha_composite(barcode, (x0 + card_w - 170, y0 + 396))

    # Evidence stamp.
    stamp = Image.new("RGBA", (170, 140), (0, 0, 0, 0))
    stamp_draw = ImageDraw.Draw(stamp)
    stamp_draw.rounded_rectangle([6, 6, 164, 134], radius=12, outline=(178, 60, 60, 150), width=4)
    stamp_draw.text((40, 28), "NCB", font=_load_font(28, bold=True), fill=(178, 60, 60, 150))
    stamp_title = "LOGGED"
    stamp_draw.text(
        ((170 - stamp_draw.textlength(stamp_title, font=_load_font(16))) / 2, 78),
        stamp_title, font=_load_font(16), fill=(178, 60, 60, 150),
    )
    stamp = stamp.rotate(13, resample=Image.BICUBIC, expand=False)
    card.alpha_composite(stamp, (x0 + 76, y0 + 306))

    stack.alpha_composite(card)
    stack = stack.rotate(-1.7, resample=Image.BICUBIC, center=(width / 2, height / 2))
    base.alpha_composite(stack)

    # Photographic grain + vignette. The grain is generated from the seeded
    # random generator (not PIL's global RNG) so the whole image is fully
    # deterministic per Test ID: a deleted evidence file can be re-created
    # byte-for-byte, keeping every stored SHA-256 fingerprint valid.
    noise = Image.new("RGB", (width, height))
    noise.putdata([rng.randint(0, 255) for _ in range(width * height)])
    out = Image.blend(base.convert("RGB"), noise, 0.05)
    vignette = ImageOps.invert(Image.radial_gradient("L").resize((width, height)))
    out = Image.composite(out, Image.blend(out, Image.new("RGB", (width, height), (18, 14, 10)), 0.3), vignette)

    out.save(str(path), "PNG")


# ---------------------------------------------------------------------------
# Initial test records
# ---------------------------------------------------------------------------

def seed_if_empty() -> None:
    database.init_db()

    if database.record_counts()["total"] == 0:
        seed_initial_records()

    # Regenerate any evidence file that has been deleted or never written so
    # every record always has a viewable image (seeded records reproduce
    # byte-for-byte, keeping their stored SHA-256 fingerprint valid).
    ensure_evidence_images()


# Records sealed at first launch; the baseline snapshot is defined by these
# together with _SAMPLE IDs and classifications.
_SEALED_BASELINE = (
    "NCB-20260919-002",
    "NCB-20260919-003",
    "NCB-20260919-010",
)

_EXPECTED_IDS = {sample["test_id"] for sample in _SAMPLES}


def _canonical_ok() -> bool:
    """The store matches the demo baseline structure: exactly the seeded
    10 records with 3 sealed (002 / 003 / 010). Field edits such as a changed
    classification are deliberately NOT treated as drift - they are the
    tamper-detection demonstration and must survive re-runs and refreshes.
    """
    rows = database.list_records()
    if len(rows) != len(_SAMPLES):
        return False
    by_id = {row["test_id"]: row for row in rows}
    if set(by_id) != _EXPECTED_IDS:
        return False
    sealed = {
        row["test_id"]
        for row in rows
        if row["certification_status"] == database.CERT_STATUS_SEALED
    }
    return sealed == set(_SEALED_BASELINE)


def _purge_non_seed_evidence() -> None:
    expected = {f"{sample['test_id']}.png" for sample in _SAMPLES}
    for path in database.EVIDENCE_DIR.glob("*.png"):
        if path.name not in expected:
            try:
                path.unlink()
            except OSError:
                pass


def restore_canonical_if_deviated(skip: bool = False) -> bool:
    """Re-seed the store when its structure no longer matches the baseline.

    Runs on every app re-run and browser refresh so the dashboard always shows
    the same 10 test records with the same 3 sealed dockets. Field edits via
    Record Review (e.g. a changed classification) are preserved so the tamper
    demonstration survives; they are not treated as drift. Returns True when
    the store had drifted and was reset.
    """
    database.init_db()
    if skip:
        return False
    if _canonical_ok():
        ensure_evidence_images()
        return False
    database.clear_all()
    _purge_non_seed_evidence()
    seed_initial_records()
    return True


def _classification_color(classification: str | None) -> tuple:
    label = str(classification or "").upper()
    if label == "POSITIVE":
        return (176, 68, 62)      # red
    if label == "INCONCLUSIVE":
        return (208, 122, 47)     # orange
    return (94, 138, 100)         # green (NEGATIVE / default)


def ensure_evidence_images() -> None:
    """Recreate missing evidence images from record metadata.

    Evidence rendering is fully deterministic (seeded random generator keyed on
    the Test ID), so re-created images for seeded records are byte-identical
    and the original stored hash still verifies. Registered records fall back
    to their declared classification colour so the docket stays viewable.
    """
    for record in database.list_records():
        path = database.evidence_path(record["image_name"])
        if path.exists():
            continue
        test_id = record["test_id"]
        color = _COLOR_BY_ID.get(test_id) or _classification_color(record.get("classification"))
        serial = f"{test_id.split('-', 1)[1]}"
        seed = int("".join(ch for ch in test_id if ch.isdigit()))
        _make_evidence(path, color, serial, seed)


def seed_initial_records() -> None:
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for sample in _SAMPLES:
        image_name = f"{sample['test_id']}.png"
        path = database.EVIDENCE_DIR / image_name
        serial = f"{sample['test_id'].split('-', 1)[1]}"
        seed = int("".join(ch for ch in sample["test_id"] if ch.isdigit()))
        _make_evidence(path, _COLOR_BY_ID[sample["test_id"]], serial, seed)

        image_data = path.read_bytes()
        stored_hash = integrity.generate_hash(
            sample["test_id"],
            sample["timestamp"],
            sample["classification"],
            sample["source"],
            sample["area"],
            sample["district"],
            sample["latitude"],
            sample["longitude"],
            image_data,
            sample["officer_id"],
            sample["notes"],
        )

        database.insert_record({
            "test_id": sample["test_id"],
            "timestamp": sample["timestamp"],
            "classification": sample["classification"],
            "source": sample["source"],
            "area": sample["area"],
            "district": sample["district"],
            "latitude": sample["latitude"],
            "longitude": sample["longitude"],
            "image_name": image_name,
            "officer_id": sample["officer_id"],
            "notes": sample["notes"],
            "stored_hash": stored_hash,
            "created_at": created_at,
        })

        audit.log_action(
            sample["test_id"],
            "RECORD CREATED",
            sample["officer_id"],
            f"Test record created from edge submission ({sample['source']}).",
        )

    # Three pre-certified dockets so the sealed repository reflects an active
    # court workflow on first launch. The stored SHA-256 hash is preserved
    # untouched. The remaining positive findings (NCB-20260919-001 / -004 /
    # -009) stay in the Pending Section 52A queue, keeping the dashboard at a
    # stable baseline of 10 records, 3 sealed and 3 pending.
    sealed = [
        ("NCB-20260919-002", "MAGISTRATE-1204", "2026-09-20 11:05:41"),
        ("NCB-20260919-003", "MAGISTRATE-1204", "2026-09-20 11:32:57"),
        ("NCB-20260919-010", "MAGISTRATE-1204", "2026-09-20 14:10:12"),
    ]
    for test_id, magistrate_id, certification_ts in sealed:
        database.certify_record(test_id, magistrate_id, certification_ts=certification_ts)
        audit.log_action(
            test_id,
            "MAGISTRATE_CERTIFIED",
            magistrate_id,
            "Evidence certified and SHA-256 hash locked for trial.",
        )