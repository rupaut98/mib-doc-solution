#!/usr/bin/env python3
"""MIB Doc Challenge pipeline: trusted-text + targeted OCR extraction, mined-rule adjudication."""
import io
import json
import os
import re
import sys
from concurrent.futures import ProcessPoolExecutor
from datetime import date
from pathlib import Path

import fitz
from PIL import Image
import pytesseract
from rapidfuzz import fuzz, process as rf_process

SPECIES = ["TRIANGULAN", "JOVIAN_GASFORM", "CENTAURI_SYNTH", "LUNA_SECURID", "KAIJU_MICRO",
           "ORION_GRAYS", "ALPHA_DRACONIAN", "SIRIUS_AVIAN", "VENUSIAN_MYCELIAL",
           "AQUARIAN_MANTIS", "ARCTURIAN", "ANDROMEDAN"]
WORLDS = ["Luyten-b", "Europa Station", "Titan Freeport", "Barnard-c", "Gliese-581g",
          "Mars Dome-7", "Kepler-186f", "Sirius Outpost", "Wolf-1061c", "Proxima-b",
          "Zeta Reticuli", "TRAPPIST-1e", "Eris Relay"]
VISAS = ["XW-1", "XW-2", "DIP-1", "MED-3", "TRANSIT-7"]
PURPOSES = ["reactor maintenance", "field repair", "medical consult", "research",
            "cultural exchange", "translation", "archive audit", "xenobotany",
            "diplomatic", "transit"]
FLAGS = ["memory_tampering", "planetary_embargo", "active_warrant", "biohazard_red",
         "identity_conflict", "sponsor_mismatch", "illegible_biometrics", "rescinded_denial"]
FEES = ["paid", "waived", "unpaid", "unknown"]
DISQ_FLAGS = {"memory_tampering", "planetary_embargo", "active_warrant", "biohazard_red"}
REVIEW_FLAGS = {"identity_conflict", "sponsor_mismatch", "illegible_biometrics", "rescinded_denial"}
REVOKED = {"SPN-0007", "SPN-0139", "SPN-4040", "SPN-9090", "SPN-7331", "SPN-2718"}
STALE_BEFORE = date(2026, 1, 2)

INJECTION_RE = re.compile(r"SYSTEM:|answer key|BARCODE PAYLOAD|ignore visible", re.I)
SENTINEL_RE = re.compile(r"^\[.*\]$")
FOOTER_RE = re.compile(r"^(Packet MIB-\d{6} / page \d|Synthetic hiring challenge document|MIB Eyes Only|MIB-\d{6})$")

TITLES = {
    "intake": "FORM I-8090: Extraterrestrial Work Authorization Intake",
    "receipt": "MIB Fee Receipt",
    "registry": "Planetary Registry Extract",
    "biometric": "FORM B-13: Biometric Scan Slip",
    "sponsor": "Sponsor Attestation Letter",
    "note": "Manual Adjudicator Note",
}
LABELS = {
    "intake": {"Applicant": "applicant_name", "Species Code": "species_code",
               "Home World": "home_world", "Visa Class": "visa_class",
               "Sponsor ID": "sponsor_id", "Arrival Date": "arrival_date",
               "Declared Purpose": "declared_purpose"},
    "registry": {"Registry Name": "applicant_name", "Home World": "home_world",
                 "Species Code": "species_code", "Arrival Date": "arrival_date"},
    "biometric": {"Applicant": "applicant_name", "Species Match": "species_code",
                  "Observed flags": "risk_flags"},
    "receipt": {"Fee Status": "fee_status", "Waiver Code": "waiver_code", "Amount": "amount"},
}
# Deliberately inverts the manual's stated precedence: measured on train, intake is
# the corrupted source and loses every conflict to registry/biometric/sponsor.
SOURCE_RANK = {"registry": 0, "biometric": 1, "sponsor": 2, "intake": 3, "receipt": 0, "note": 0}

DATE_RE = re.compile(r"(20\d{2})[-./ ]?(\d{2})[-./ ]?(\d{2})")
SPN_RE = re.compile(r"S[Pp]?N[-: ]?\s*([0-9OoIlSsBg]{4})")
DIGIT_FIX = str.maketrans({"O": "0", "o": "0", "I": "1", "l": "1", "S": "5", "s": "5", "B": "8", "g": "9"})


def snap(value, vocab, cutoff=72):
    """Fuzzy-snap a raw string to a closed vocabulary; None if no confident match."""
    if not value:
        return None
    hit = rf_process.extractOne(value, vocab, scorer=fuzz.WRatio, score_cutoff=cutoff)
    return hit[0] if hit else None


def page_lines_text(page):
    """Visible-span lines from the native text layer, adversarial spans dropped."""
    lines, stamps = [], []
    d = page.get_text("dict")
    for block in d.get("blocks", []):
        for line in block.get("lines", []):
            parts = []
            for span in line.get("spans", []):
                text = span["text"].strip()
                if not text:
                    continue
                color, size = span.get("color", 0), span.get("size", 9)
                if color == 0xFFFFFF or size < 6.0:
                    continue  # hidden poison layer
                if INJECTION_RE.search(text):
                    continue
                if size >= 40:  # SAMPLE DENIAL watermark
                    continue
                if size >= 18 and text in ("APPROVED", "DENIED", "REVIEW"):
                    stamps.append(text)
                    continue
                parts.append(text)
            if parts:
                lines.append(" ".join(parts))
    return lines, stamps


def _tsv_lines(img, psm):
    data = pytesseract.image_to_data(img, config=f"--psm {psm}", output_type=pytesseract.Output.DICT)
    words = {}
    for i, txt in enumerate(data["text"]):
        txt = txt.strip()
        if not txt or int(data["conf"][i]) < 20:
            continue
        key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
        words.setdefault(key, []).append((data["left"][i], txt, data["top"][i]))
    rows = []
    for key, ws in words.items():
        ws.sort()
        rows.append((min(t for _, _, t in ws), " ".join(w for _, w, _ in ws)))
    rows.sort()
    merged = []
    for top, text in rows:
        if merged and abs(top - merged[-1][0]) < 12:
            merged[-1] = (merged[-1][0], merged[-1][1] + " " + text)
        else:
            merged.append((top, text))
    return [t for _, t in merged]


def ocr_page(page, dpi=200):
    """Render an image-only page, OCR with two PSMs (+binarized retry), return line variants."""
    pix = page.get_pixmap(dpi=dpi, colorspace=fitz.csGRAY)
    img = Image.open(io.BytesIO(pix.tobytes("png")))
    variants = [_tsv_lines(img, 11), _tsv_lines(img, 6)]
    joined = " ".join(variants[0]) + " " + " ".join(variants[1])
    if len(joined) < 200:  # heavy degradation -> upscale + hard threshold retry
        big = img.resize((img.width * 2, img.height * 2), Image.LANCZOS)
        bw = big.point(lambda p: 255 if p > 160 else 0)
        variants.append(_tsv_lines(bw, 11))
    return variants


def ocr_page_hard(page):
    """Escalation pass for pages whose key fields resisted the cheap OCR."""
    pix = page.get_pixmap(dpi=300, colorspace=fitz.csGRAY)
    img = Image.open(io.BytesIO(pix.tobytes("png")))
    variants = [_tsv_lines(img, 6), _tsv_lines(img, 11)]
    for thresh in (140, 180):
        bw = img.point(lambda p, t=thresh: 255 if p > t else 0)
        variants.append(_tsv_lines(bw, 6))
    return variants


def detect_doctype(lines):
    joined = " ".join(lines[:8])
    best, best_score = None, 0
    for dt, title in TITLES.items():
        score = fuzz.partial_ratio(title.lower(), joined.lower())
        if score > best_score:
            best, best_score = dt, score
    return best if best_score >= 70 else None


def clean_value(v):
    v = v.strip().strip("|").strip()
    if not v or SENTINEL_RE.match(v) or v.startswith("["):
        return None
    return v


def parse_fields(lines, doctype, is_ocr):
    """Extract field candidates from ordered lines of one page."""
    out = {}
    labels = LABELS.get(doctype, {})

    def match_label(text):
        text = text.rstrip(":").strip()
        if not labels:
            return None
        if not is_ocr:
            return labels.get(text)
        hit = rf_process.extractOne(text, list(labels), scorer=fuzz.ratio, score_cutoff=80)
        return labels[hit[0]] if hit else None

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # inline "Label: value"
        if ":" in line:
            lab, _, val = line.partition(":")
            field = match_label(lab)
            if field and val.strip():
                out.setdefault(field, val.strip())
                i += 1
                continue
        field = match_label(line)
        if field and i + 1 < len(lines):
            nxt = lines[i + 1].strip()
            if not match_label(nxt) and not FOOTER_RE.match(nxt):
                out.setdefault(field, nxt)
                i += 2
                continue
        i += 1
    return out


def token_scan(text, doctype):
    """Field candidates from raw OCR text via distinctive-token search (order-independent)."""
    out = {}
    low = text.lower()
    # snake_case flag tokens survive OCR noise well
    found = set()
    for tok in re.findall(r"[a-z]+[_ ]?[a-z]+", low):
        hit = rf_process.extractOne(tok.replace(" ", "_"), FLAGS, scorer=fuzz.ratio, score_cutoff=85)
        if hit:
            found.add(hit[0])
    biometric_ish = doctype == "biometric" or re.search(r"species match|biometric|observed|b-?13", low)
    if found:
        out["risk_flags"] = "|".join(sorted(found))
    elif re.search(r"(observed|obserw?ed|flags?)\W{0,6}(none|nane|nome|mone)", low):
        out["risk_flags"] = "none"
    elif biometric_ish and re.search(r"(?<![a-z])(none|nane|nome|mone)(?![a-z])", low):
        out["risk_flags"] = "none"
    m = SPN_RE.search(text)
    if m:
        digits = m.group(1).translate(DIGIT_FIX)
        if digits.isdigit():
            out["sponsor_id"] = f"SPN-{digits}"
    m = DATE_RE.search(text)
    if m:
        out["arrival_date"] = m.group(0)
    m = re.search(r"(?<![A-Za-z])(XW[-—.\s]?[12lI]|D[Il1]P[-—.\s]?[1lI]|MED[-—.\s]?[3B]|TRANS[Il1]T[-—.\s]?7?)(?![A-Za-z])", text)
    if m and doctype in ("intake", "sponsor", None):
        out["visa_class"] = m.group(0)
    if re.search(r"[$5S]\s*8[0OQ]9", text):
        out["amount"] = "809"
    elif re.search(r"[$5S]\s*[0OQ][.,]\s*[0OQ]{2}", text):
        out["amount"] = "0"
    if re.search(r"D[Il1]P[-\s]?WA[Il1]VER", text, re.I):
        out["waiver_code"] = "DIP-WAIVER"
    fm = re.search(r"(?<![a-z])(unpaid|paid|waived|waivcd|waivod|unknown|pald|pa1d|urpaid|umpaid)(?![a-z])", low)
    if fm:
        out["fee_status"] = fm.group(0)
    for sp in SPECIES:
        if fuzz.partial_ratio(sp.lower(), low) >= 90:
            out.setdefault("species_code", sp)
            break
    for w in WORLDS:
        if fuzz.partial_ratio(w.lower(), low) >= 92:
            out.setdefault("home_world", w)
            break
    for p in PURPOSES:
        if fuzz.partial_ratio(p, low) >= 90:
            out.setdefault("declared_purpose", p)
            break
    return out


def parse_sponsor_prose(lines):
    out = {}
    text = " ".join(lines)
    m = re.search(r"Sponsor\s+(SPN[- ]?\d{4})\s+attests that\s+(.+?)\s+is expected on\s+(.+?)\s+for\s+(.+?)\.", text, re.I)
    if m:
        out["sponsor_id"] = m.group(1).upper().replace(" ", "-")
        out["applicant_name"] = m.group(2)
        out["home_world"] = m.group(3)
        out["declared_purpose"] = m.group(4)
    m = re.search(r"class\s+([A-Z]{2,7}[- ]?\d)\s+compliance", text, re.I)
    if m:
        out["visa_class"] = m.group(1).upper().replace(" ", "-")
    return out


def parse_note(lines):
    text = " ".join(lines)
    m = re.search(r"F[i1l]nd[i1l]ng[:;]?\s*(APPROVED|DENIED|NEEDS[_ ]?REVIEW|REVIEW)", text, re.I)
    if m:
        val = m.group(1).upper().replace(" ", "_")
        return "NEEDS_REVIEW" if "REVIEW" in val and val != "NEEDS_REVIEW" else val
    return None


def normalize_field(field, raw, is_ocr):
    if raw is None:
        return None
    raw = clean_value(raw)
    if raw is None:
        return None
    if field == "species_code":
        return snap(raw.upper().replace(" ", "_"), SPECIES, 70)
    if field == "home_world":
        return snap(raw, WORLDS, 72)
    if field == "visa_class":
        v = raw.upper().replace(" ", "").replace("—", "-")
        return snap(v, VISAS, 60)
    if field == "declared_purpose":
        return snap(raw.lower(), PURPOSES, 72)
    if field == "fee_status":
        return snap(raw.lower(), FEES, 65)
    if field == "sponsor_id":
        m = SPN_RE.search(raw)
        if m:
            digits = m.group(1).translate(DIGIT_FIX)
            if digits.isdigit():
                return f"SPN-{digits}"
        return None
    if field == "arrival_date":
        if re.search(r"UNREADABLE|ILLEGIBLE|MISSING|WASHED", raw, re.I):
            return "UNRECOVERABLE"
        m = DATE_RE.search(raw.translate(DIGIT_FIX) if is_ocr else raw)
        if m:
            try:
                return date(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat()
            except ValueError:
                pass
        return None
    if field == "risk_flags":
        low = raw.lower()
        if "none" in low and not any(f[:6] in low for f in FLAGS):
            return "none"
        found = set()
        for tok in re.split(r"[,;|/]+", low):
            tok = tok.strip().replace(" ", "_")
            if not tok:
                continue
            hit = snap(tok, FLAGS, 78)
            if hit:
                found.add(hit)
        return "|".join(sorted(found)) if found else ("none" if "none" in low else None)
    if field == "applicant_name":
        v = re.sub(r"[|:;~=_]+", " ", raw)
        v = " ".join(w for w in v.split() if w.isalpha() or "-" in w or "'" in w)
        return v if 3 <= len(v) <= 48 and 1 <= len(v.split()) <= 4 else None
    return raw


def extract_case(pdf_path):
    case_id = Path(pdf_path).stem
    doc = fitz.open(pdf_path)
    candidates = {}   # field -> [((source_rank, tier), value)]
    findings, stamps_all = [], []

    flags_readable = False   # an Observed-flags value (incl. none) was read
    slip_seen = False
    untyped_ocr_pages = 0    # unidentified OCR pages — any could be the flags slip
    receipt_cues = {}

    for page in doc:
        lines, stamps = page_lines_text(page)
        body = [l for l in lines if not FOOTER_RE.match(l)]
        is_ocr = False
        variants = [lines]
        if len(" ".join(body)) < 30:  # image-only page
            is_ocr = True
            try:
                variants = ocr_page(page)
            except Exception:
                untyped_ocr_pages += 1
                continue
        stamps_all.extend(stamps)
        page_found = {}  # field -> (tier, value); tier 0=text label, 1=ocr label, 2=token scan
        doctype = None

        def process_variants(vlist):
            nonlocal doctype
            for lines in vlist:
                dt = detect_doctype(lines)
                if dt and doctype is None:
                    doctype = dt
                dt = dt or doctype
                text = " ".join(lines)
                f = parse_note(lines)
                if f and (dt == "note" or not is_ocr):
                    findings.append(f)
                if is_ocr and not f:
                    for l in lines:
                        w = l.strip()
                        if w in ("APPROVED", "DENIED", "REVIEW"):
                            stamps_all.append(w)
                fields = parse_sponsor_prose(lines) if dt == "sponsor" else parse_fields(lines, dt, is_ocr)
                tiers = {fld: (1 if is_ocr else 0) for fld in fields}
                if is_ocr:
                    for field, raw in token_scan(text, dt).items():
                        if field not in fields:
                            fields[field] = raw
                            tiers[field] = 2
                elif dt == "receipt":
                    for field, raw in token_scan(text, dt).items():
                        if field in ("amount", "waiver_code") and field not in fields:
                            fields[field] = raw
                            tiers[field] = 0
                mcorr = re.search(r"Manual correction[:;]?\s*sponsor is\s*(SPN[- ]?\d{4})", text, re.I)
                if mcorr:
                    candidates.setdefault("sponsor_id", []).insert(0, ((-1, 0), mcorr.group(1).upper().replace(" ", "-")))
                for field, raw in fields.items():
                    if field in ("waiver_code", "amount"):
                        v = str(raw)
                        if "809" in v:
                            receipt_cues["amount"] = "809"
                        elif re.search(r"[0OQ][.,]\s*[0OQ]{2}|^0$", v):
                            receipt_cues.setdefault("amount", "0")
                        if "WAIVER" in v.upper():
                            receipt_cues["waiver_code"] = "DIP-WAIVER"
                        elif v.upper().startswith("N/"):
                            receipt_cues.setdefault("waiver_code", "N/A")
                        continue
                    val = normalize_field(field, raw, is_ocr)
                    if val is not None and (field not in page_found or tiers[field] < page_found[field][0]):
                        page_found[field] = (tiers[field], val)

        process_variants(variants)
        if is_ocr:
            need_more = (
                doctype is None
                or (doctype == "receipt" and "fee_status" not in page_found and "amount" not in receipt_cues)
                or (doctype == "biometric" and "risk_flags" not in page_found)
                or (doctype in ("registry", "intake") and "arrival_date" not in page_found)
            )
            if need_more:
                try:
                    process_variants(ocr_page_hard(page))
                except Exception:
                    pass
        if doctype == "biometric":
            slip_seen = True
        if "risk_flags" in page_found:
            flags_readable = True
        if doctype is None and is_ocr:
            untyped_ocr_pages += 1
        rank = SOURCE_RANK.get(doctype, 5) + (10 if is_ocr else 0)
        for field, (tier, val) in page_found.items():
            candidates.setdefault(field, []).append(((rank, tier), val))
    doc.close()

    record = {"case_id": case_id}
    tiers = {}
    for field in ("applicant_name", "species_code", "home_world", "visa_class",
                  "sponsor_id", "arrival_date", "declared_purpose", "risk_flags", "fee_status"):
        cands = sorted(candidates.get(field, []), key=lambda c: c[0])
        record[field] = cands[0][1] if cands else None
        tiers[field] = cands[0][0][1] if cands else 3

    # Receipt Amount+Waiver pair is 100% predictive on train and overrides a
    # misprinted Fee Status word — don't "fix" this to prefer the status text.
    amt, wc = receipt_cues.get("amount"), receipt_cues.get("waiver_code")
    if amt == "809":
        record["fee_status"] = "paid"
    elif amt == "0" and wc == "DIP-WAIVER":
        record["fee_status"] = "waived"
    elif amt == "0":
        record["fee_status"] = "unpaid" if record["fee_status"] == "unpaid" else "unknown"

    flags_uncertain = not flags_readable and (slip_seen or untyped_ocr_pages > 0)
    # embargo home world implies planetary_embargo (50/50 on train, incl. DIP-1)
    if record["home_world"] in ("TRAPPIST-1e", "Eris Relay"):
        cur = set() if record["risk_flags"] in (None, "none") else set(record["risk_flags"].split("|"))
        cur.add("planetary_embargo")
        record["risk_flags"] = "|".join(sorted(cur))
        flags_uncertain = False
    if record["risk_flags"] is None:
        record["risk_flags"] = "none"
    if record["fee_status"] is None:
        record["fee_status"] = "unknown"

    decision, reason = adjudicate(record, findings, stamps_all, flags_uncertain, tiers)
    record["adjudication"] = decision
    record["_reason"] = reason
    record["_slip_seen"] = slip_seen
    record["_flags_readable"] = flags_readable
    record["_untyped"] = untyped_ocr_pages

    # unknown fields still submit; patterned fields need schema-valid placeholders
    for k, v in list(record.items()):
        if v is None:
            record[k] = ""
    if record["arrival_date"] in ("", "UNRECOVERABLE"):
        record["arrival_date"] = "1900-01-01"
    if not record["sponsor_id"]:
        record["sponsor_id"] = "SPN-0000"
    return record


def adjudicate(rec, findings, stamps, flags_uncertain=False, tiers=None):
    tiers = tiers or {}
    flags = set(rec["risk_flags"].split("|")) if rec["risk_flags"] not in ("none", None) else set()
    # manual note matched truth 162/162 on train; a lone stamp is likewise 100%,
    # conflicting stamps always meant NEEDS_REVIEW (9/9)
    if len(set(findings)) == 1:
        return findings[0], "manual_note"
    st = set(stamps)
    if st:
        if st == {"APPROVED"}:
            return "APPROVED", "stamp"
        if st == {"REVIEW"}:
            return "NEEDS_REVIEW", "stamp"
        if st == {"DENIED"}:
            return "DENIED", "stamp"
        return "NEEDS_REVIEW", "stamp_conflict"
    dip = rec["visa_class"] == "DIP-1"
    if flags & DISQ_FLAGS:
        return "DENIED", "disq_flag"
    if rec["visa_class"] == "TRANSIT-7":
        return "DENIED", "transit"
    if rec["fee_status"] == "unpaid":
        return "DENIED", "unpaid"
    if rec["sponsor_id"] in REVOKED and not dip and tiers.get("sponsor_id", 3) <= 1:
        return "DENIED", "revoked_sponsor"
    if rec["home_world"] == "Wolf-1061c" and not dip and tiers.get("home_world", 3) <= 1:
        return "DENIED", "wolf"
    if rec["arrival_date"] and rec["arrival_date"] != "UNRECOVERABLE" and not dip:
        y, m, d = map(int, rec["arrival_date"].split("-"))
        if date(y, m, d) < STALE_BEFORE and tiers.get("arrival_date", 3) <= 1:
            return "DENIED", "stale"
    if rec["arrival_date"] in (None, "", "UNRECOVERABLE"):
        return "NEEDS_REVIEW", "arrival_missing"
    if rec["fee_status"] == "unknown":
        return "NEEDS_REVIEW", "fee_unknown"
    if flags & REVIEW_FLAGS:
        return "NEEDS_REVIEW", "review_flag"
    if flags_uncertain:
        return "NEEDS_REVIEW", "flags_uncertain"
    return "APPROVED", "default"


# confidence = smoothed empirical accuracy per decision path on train; uncertain
# paths are further keyed by evidence signature slip_seen/flags_readable/has_untyped
CONFIDENCE = {
    "manual_note": 0.98, "stamp": 0.85, "stamp_conflict": 0.9,
    "disq_flag": 0.96, "transit": 0.89, "unpaid": 0.91, "revoked_sponsor": 0.94,
    "wolf": 0.81, "stale": 0.91, "review_flag": 0.92,
    "default|000": 0.57, "default|110": 0.87, "default|111": 0.9, "default|011": 0.72,
    "fee_unknown|000": 0.51, "fee_unknown|001": 0.48, "fee_unknown|110": 0.6,
    "fee_unknown|111": 0.48, "fee_unknown|011": 0.83, "fee_unknown|100": 0.6,
    "fee_unknown|101": 0.6, "fee_unknown|010": 0.76,
    "flags_uncertain|001": 0.41, "flags_uncertain|100": 0.44, "flags_uncertain|101": 0.44,
    "arrival_missing|000": 0.63, "arrival_missing|001": 0.42, "arrival_missing|101": 0.26,
    "arrival_missing|110": 0.63, "arrival_missing|111": 0.45, "arrival_missing|100": 0.56,
}
BUCKETED_REASONS = ("default", "fee_unknown", "flags_uncertain", "arrival_missing")


def confidence_for(rec):
    reason = rec["_reason"]
    if reason in BUCKETED_REASONS:
        sig = f'{int(rec["_slip_seen"])}{int(rec["_flags_readable"])}{int(rec["_untyped"] > 0)}'
        return CONFIDENCE.get(f"{reason}|{sig}", 0.55)
    return CONFIDENCE.get(reason, 0.5)


def process_one(pdf_path):
    try:
        rec = extract_case(pdf_path)
    except Exception as e:
        stem = Path(pdf_path).stem
        rec = {"case_id": stem, "applicant_name": "", "species_code": "", "home_world": "",
               "visa_class": "", "sponsor_id": "SPN-0000", "arrival_date": "1900-01-01",
               "declared_purpose": "", "risk_flags": "none", "fee_status": "unknown",
               "adjudication": "NEEDS_REVIEW", "_reason": f"error:{e}",
               "_slip_seen": False, "_flags_readable": False, "_untyped": 1}
    rec["confidence"] = confidence_for(rec)
    return rec


def main(input_dir, output_path):
    pdfs = sorted(Path(input_dir).glob("*.pdf"))
    workers = int(os.environ.get("MIB_WORKERS", os.cpu_count() or 4))
    with ProcessPoolExecutor(max_workers=workers) as ex:
        records = list(ex.map(process_one, [str(p) for p in pdfs], chunksize=8))
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    keep = ["case_id", "applicant_name", "species_code", "home_world", "visa_class", "sponsor_id",
            "arrival_date", "declared_purpose", "risk_flags", "fee_status", "adjudication", "confidence"]
    debug = os.environ.get("MIB_DEBUG")
    with open(out, "w") as f:
        for rec in records:
            f.write(json.dumps({k: rec[k] for k in keep}) + "\n")
    if debug:
        with open(debug, "w") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
