# =========================
# Forms Analyzer Pro (2025-09) — 3rd-party aware
# =========================
import os, re, io, uuid, json, time, logging, argparse, csv
from datetime import datetime
from pathlib import Path

import requests
import fitz  # PyMuPDF
import pdfplumber

# Optional deps (graceful fallback)
try:
    from pyhanko.sign.general import gather_signatures
    from pyhanko.pdf_utils.reader import PdfFileReader
    _HAS_PYHANKO = True
except Exception:
    _HAS_PYHANKO = False

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except Exception:
    _HAS_TLDEXTRACT = False

try:
    import yaml  # for brands.yml
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("forms-analyzer-nigo")

# ---------- Patterns / constants ----------
SIG_PATTERNS     = [r"\bsignature\b", r"\bsign\b", r"\bsigned\b", r"\bsignatory\b", r"\bexecute(d)?\b"]
WITNESS_PATTERNS = [r"\bwitness\b", r"\bwitness(ed|ing)?\b", r"\battested\b"]
NOTARY_PATTERNS  = [r"\bnotary\b", r"\bnotariz(ed|ation)\b", r"\backnowledged\b", r"\bsworn\b", r"\baffirmed\b"]

PII_PATTERNS = {
    "ssn":  r"\b(ssn|social security number)\b",
    "dob":  r"\b(date of birth|dob)\b",
    "tin":  r"\b(tin|taxpayer identification)\b",
    "ein":  r"\b(employer identification number|ein)\b",
    "dl":   r"\b(driver'?s license|state id)\b",
    "acct": r"\b(account number|routing number|iban)\b",
    "addr": r"\b(address|street|city|state|zip)\b",
    "phone":r"\b(phone|telephone|cell)\b",
    "email":r"\b(email)\b",
}

ATTACHMENT_HINTS = [
    r"\battach(ed)?\b",
    r"\b(include|provide)\s+(a|an|the)?\s*(copy|document|proof)\b",
    r"\bvoided check\b",
    r"\bphoto id\b",
    r"\b(driver'?s license|passport)\b",
    r"\b(account statement|bank statement)\b",
    r"\bsupporting (documents|documentation)\b",
]

ROLE_HINTS = {
    "applicant": r"\b(applicant|borrower|member)\s+signature\b",
    "co_owner":  r"\b(co[-\s]?owner|co[-\s]?applicant)\s+signature\b",
    "guardian":  r"\b(parent|guardian)\s+signature\b",
    "spouse":    r"\b(spouse)\s+signature\b",
    "officer":   r"\b(officer|authorized signer)\s+signature\b",
    "witness":   r"\bwitness\s+signature\b",
    "notary":    r"\bnotary\s+(public|signature)\b",
}

# ---- Third-party role detection ----
THIRD_PARTY_PATTERNS = {
    "Witness":            r"\bwitness\b",
    "Physician":          r"\b(physician|doctor|md|do)\b",
    "Financial Advisor":  r"\b(financial advisor|advisor|adviser|ria|broker-dealer|broker)\b",
    "Attorney":           r"\b(attorney|lawyer|counsel|esq\.?)\b",
    "Guardian/POA":       r"\b(guardian|conservator|power of attorney|poa|agent under poa)\b",
    "Employer/HR":        r"\b(employer|human resources|hr department|hr rep|supervisor)\b",
    "Court/Clerk":        r"\b(court clerk|clerk of court|court)\b",
}
CORE_SIGNER_TERMS = {"Applicant","Borrower","Member","Customer","Account Holder","Co-owner","Co-applicant","Spouse"}

LABEL_SEARCH_PAD = 20
FIELD_CLASS_PATTERNS = [
    ("ssn", r"\b(ssn|social security)\b"), ("tin", r"\b(tin|taxpayer)\b"),
    ("ein", r"\b(ein|employer id(entification)?)\b"), ("dob", r"\b(date of birth|dob)\b"),
    ("date", r"\b(date)\b"), ("phone", r"\b(phone|telephone|cell)\b"),
    ("email", r"\b(e[- ]?mail)\b"), ("zip", r"\b(zip|postal)\b"),
    ("state", r"\b(state|prov(ince)?)\b"), ("routing", r"\b(routing|aba)\b"),
    ("account", r"\b(account|acct)\b"), ("amount", r"\b(amount|usd|\$)\b"),
    ("signature", r"\b(signature)\b"), ("notary", r"\b(notary)\b"), ("witness", r"\b(witness)\b"),
]

# NIGO scoring knobs
HIGH_RISK_FIELDS = {"ssn","dob","routing","account","email","phone","zip","state","tin","ein"}
RULE_WEIGHTS     = {"REQ-001":5,"FMT-001":8,"SIG-002":4,"COND-003":6,"ROLE-001":6,"THRD-001":6}
SEVERITY_WEIGHTS = {"high":20,"medium":12,"low":6}

# Deadline + dependency patterns
DEPENDENCY_PATTERNS = [
    ("with",   r"\b(submit|send|file|include)\s+(this\s+)?form\s+(with|along with)\s+(form\s+)?([A-Za-z0-9\-_/\.]+)"),
    ("with",   r"\b(accompany|in conjunction with|together with|in addition to)\s+(form\s+)?([A-Za-z0-9\-_/\.]+)"),
    ("before", r"\b(before|prior to)\s+(submitting|sending)\s+(this\s+)?form.*?\b(form\s+)?([A-Za-z0-9\-_/\.]+)"),
    ("after",  r"\b(after|following)\s+(approval|submission|receipt)\s+of\s+(form\s+)?([A-Za-z0-9\-_/\.]+)"),
    ("see",    r"\b(see|refer to)\s+(form|document)\s+([A-Za-z0-9\-_/\.]+)"),
]
FORM_TOKEN = r"((SF|GSA|SSA|IRS|USCIS|I|DS|W|POA|DPOA|DOA|F|FRM|APP|ACCT|CHG)[\-\s]?\d+[A-Za-z0-9\-]*)"

DEADLINE_PATTERNS = [
    r"\b(within\s+\d{1,3}\s+(calendar|business)\s+days)\b",
    r"\b(within\s+\d{1,2}\s+months?)\b",
    r"\b(no\s+later\s+than\s+\d{1,3}\s+(days|business days))\b",
    r"\b(by\s+(?:the\s+)?\d{1,2}\/\d{1,2}\/\d{2,4})\b",
    r"\b(by\s+(?:the\s+)?[A-Za-z]{3,9}\s+\d{1,2},\s+\d{4})\b",
    r"\b(postmarked\s+within\s+\d{1,3}\s+days)\b",
    r"\b(\d{1,3}\s+(calendar|business)\s+days\s+of\s+(?:receipt|effective\s+date|notification))\b",
    # broadened
    r"\bon or before\s+\d{1,2}/\d{1,2}/\d{2,4}\b",
    r"\bon or before\s+[A-Za-z]{3,9}\s+\d{1,2},\s+\d{4}\b",
    r"\bmust be (?:received|submitted|returned)\s+within\s+\d{1,3}\s+(?:days|business days|weeks|months)\b",
    r"\bno later than\b",
    r"\bon or before\b",
    r"\bwithin\s+\d{1,3}\s+(?:days|business days|weeks|months)\b",
    r"\bpostmarked by\b",
    r"\beffective date\b.*?\bwithin\s+\d{1,3}\s+(?:days|business days)\b",
]

# ---------- brand config loader ----------
def load_brand_config(config_path: Path) -> dict:
    """
    Load issuer->domains map from YAML at config/brands.yml.
    Fallback to built-ins if missing or PyYAML not available.
    """
    builtin = {
        "Fidelity Investments": ["fidelity.com","fmr.com"],
        "Charles Schwab": ["schwab.com","schwabcdn.com"],
        "Vanguard": ["vanguard.com"],
        "JPMorgan Chase": ["chase.com","jpmorganchase.com","jpmorgan.com"],
        "Cigna": ["cigna.com"], "Aetna": ["aetna.com"],
        "UnitedHealthcare": ["uhc.com","optum.com"],
        "GSA": ["gsa.gov"], "USCIS": ["uscis.gov"],
        "IRS": ["irs.gov","treasury.gov"], "SSA": ["ssa.gov"],
        "U.S. Bank": ["usbank.com"], "PNC": ["pnc.com"],
        "Bank of America": ["bankofamerica.com","bofa.com"],
        "Morgan Stanley": ["morganstanley.com"],
    }
    if not config_path.exists() or not _HAS_YAML:
        return builtin
    try:
        with config_path.open("r", encoding="utf-8") as f:
            y = yaml.safe_load(f) or {}
        out = {}
        for k,v in (y.get("brands") or y).items():
            if isinstance(v, (list,tuple)):
                out[str(k)] = [str(d).lower() for d in v]
        return out or builtin
    except Exception as e:
        log.warning(f"brands.yml load failed: {e}")
        return builtin
# ---------- smart downloader ----------
def _download(url: str) -> io.BytesIO:
    log.info(f"Downloading: {url}")
    sess = requests.Session()
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url); origin = f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        origin = "https://www.google.com"
    headers = {
        "User-Agent":"Mozilla/5.0",
        "Accept":"application/pdf,*/*;q=0.9",
        "Accept-Language":"en-US,en;q=0.9",
        "Referer": origin,
        "Connection":"keep-alive",
        "Cache-Control":"no-cache",
        "Pragma":"no-cache",
    }
    if "fidelity.com" in url:
        try:
            sess.get("https://www.fidelity.com/customer-service/forms-applications/all-forms",
                     headers=headers, timeout=20, allow_redirects=True)
        except Exception:
            pass
    last = None
    for attempt in range(3):
        try:
            r = sess.get(url, headers=headers, timeout=40, allow_redirects=True)
            r.raise_for_status()
            if not r.content.startswith(b"%PDF"):
                raise ValueError("Content not a PDF")
            return io.BytesIO(r.content)
        except Exception as e:
            last = e; time.sleep(0.8*(attempt+1))
    raise last or RuntimeError("Failed to download PDF")

def _open_doc(pdf_stream: io.BytesIO):
    pdf_stream.seek(0)
    return fitz.open(stream=pdf_stream.read(), filetype="pdf")

# ---------- text normalization ----------
def _normalize_text_for_rules(raw: str) -> str:
    if not raw: return ""
    t = re.sub(r"(\w)-\s*\n\s*(\w)", r"\1\2", raw)  # join hyphenated breaks
    t = re.sub(r"\s*\n\s*", " ", t)                 # collapse newlines
    t = re.sub(r"\s{2,}", " ", t)                   # shrink spaces
    return t

# ---------- extraction ----------
def extract_text(pdf_stream: io.BytesIO) -> str:
    try:
        pdf_stream.seek(0)
        with pdfplumber.open(pdf_stream) as pdf:
            txt = []
            for p in pdf.pages:
                t = p.extract_text() or ""
                if t: txt.append(t)
            return _normalize_text_for_rules(("\n".join(txt)).lower())
    except Exception as e:
        log.warning(f"pdfplumber failed: {e}")
    try:
        doc = _open_doc(pdf_stream)
        txt = []
        for p in doc:
            txt.append(p.get_text("text") or "")
        doc.close()
        return _normalize_text_for_rules(("\n".join(txt)).lower())
    except Exception as e:
        log.error(f"text extraction failed: {e}")
        return ""

def count_fields(pdf_stream: io.BytesIO) -> dict:
    out = {"total":0,"text_fields":0,"checkboxes":0,"dropdowns":0,"signatures":0}
    try:
        doc = _open_doc(pdf_stream)
        for page in doc:
            for w in (page.widgets() or []):
                out["total"] += 1
                t = getattr(w, "field_type", None)
                if t == fitz.PDF_WIDGET_TYPE_TEXT: out["text_fields"] += 1
                elif t == fitz.PDF_WIDGET_TYPE_CHECKBOX: out["checkboxes"] += 1
                elif t in (fitz.PDF_WIDGET_TYPE_COMBOBOX, fitz.PDF_WIDGET_TYPE_LISTBOX): out["dropdowns"] += 1
                elif t == fitz.PDF_WIDGET_TYPE_SIGNATURE or getattr(w, "is_signature", False): out["signatures"] += 1
        doc.close()
    except Exception as e:
        log.warning(f"count_fields fallback: {e}")
    return out

def count_attachments(pdf_stream: io.BytesIO) -> int:
    try:
        doc = _open_doc(pdf_stream)
        try:
            n = getattr(doc, "embedded_file_count")
            cnt = int(n() if callable(n) else n)
        except Exception:
            try:
                n = getattr(doc, "embeddedFileCount")
                cnt = int(n() if callable(n) else n)
            except Exception:
                cnt = 0
        doc.close()
        return cnt or 0
    except Exception as e:
        log.warning(f"attachment detect failed: {e}")
        return 0

def detect_js(pdf_stream: io.BytesIO) -> str:
    """Doc/page/widget actions; fallback to radio inference."""
    try:
        doc = _open_doc(pdf_stream)
        try:
            if hasattr(doc,"get_actions") and (doc.get_actions() or {}): doc.close(); return "Yes"
        except Exception: pass
        try:
            if hasattr(doc,"has_js") and doc.has_js(): doc.close(); return "Yes"
        except Exception: pass
        for page in doc:
            try:
                if page.get_actions(): doc.close(); return "Yes"
            except Exception: pass
            try:
                if page.get_javascript(): doc.close(); return "Yes"
            except Exception: pass
            try:
                for w in (page.widgets() or []):
                    try:
                        if (w.get_actions() or {}): doc.close(); return "Yes"
                    except Exception: pass
            except Exception: pass
        # radio inference
        radios = 0
        try:
            for p in doc:
                for w in (p.widgets() or []):
                    if getattr(w,"field_type",None) == fitz.PDF_WIDGET_TYPE_RADIOBUTTON:
                        radios += 1
                        if radios >= 2:
                            doc.close(); return "Yes"
        except Exception: pass
        doc.close()
        return "No"
    except Exception:
        return "No"
# ---------- deps & deadlines ----------
def detect_dependencies(text: str) -> list:
    if not text: return []
    deps, low = [], text.lower()
    for rel, pat in DEPENDENCY_PATTERNS:
        for m in re.finditer(pat, low, flags=re.I|re.S):
            snippet = m.group(0)[:180]
            fid = None
            fm = re.search(FORM_TOKEN, snippet, flags=re.I)
            if fm: fid = fm.group(1).upper().replace("  ", " ")
            deps.append({"relation": rel, "hint": snippet.strip(), "form_id": fid})
    # de-dupe
    uniq, seen = [], set()
    for d in deps:
        key = (d["relation"], d.get("form_id") or d["hint"])
        if key not in seen:
            uniq.append(d); seen.add(key)
    return uniq

def detect_deadlines(text: str) -> list:
    if not text: return []
    hits = set()
    for pat in DEADLINE_PATTERNS:
        for m in re.finditer(pat, text, flags=re.I):
            hits.add(m.group(0).strip())
    return sorted(hits)

# ---------- roles & graphics ----------
def detect_roles(text: str) -> list:
    roles = []
    for role, pat in ROLE_HINTS.items():
        if re.search(pat, text, re.I): roles.append(role)
    return roles

def count_radio_groups(pdf_stream: io.BytesIO) -> int:
    groups = set()
    try:
        doc = _open_doc(pdf_stream)
        for page in doc:
            for w in (page.widgets() or []):
                try:
                    if getattr(w,"field_type",None) == fitz.PDF_WIDGET_TYPE_RADIOBUTTON:
                        name = (w.field_name or "").split(".")[0]
                        if name: groups.add(name)
                except Exception: pass
        doc.close()
    except Exception: pass
    return len(groups)

def page_graphics_stats(pdf_stream: io.BytesIO) -> dict:
    stats = {"images_per_page":0.0,"drawings_per_page":0.0,"text_density":0.0}
    try:
        doc = _open_doc(pdf_stream)
        pages = max(1, len(doc))
        img_total, draw_total, char_total = 0, 0, 0
        for p in doc:
            try: img_total += len(p.get_images(full=True) or [])
            except Exception: pass
            try: draw_total += len(p.get_drawings() or [])
            except Exception: pass
            try: char_total += len(p.get_text("text") or "")
            except Exception: pass
        doc.close()
        stats["images_per_page"]  = round(img_total / pages, 2)
        stats["drawings_per_page"]= round(draw_total / pages, 2)
        stats["text_density"]     = round(char_total / pages, 2)
    except Exception: pass
    return stats

def xfa_like_hint(text: str, meta: dict) -> bool:
    joined = f"{json.dumps(meta or {})}\n{text or ''}".lower()
    return any(k in joined for k in ["xfa","dynamic xdp","xfa form","livecycle"])

def _label_near_widget(doc, page, widget) -> str:
    try:
        rect = widget.rect
        search = fitz.Rect(rect.x0-200, rect.y0-40-LABEL_SEARCH_PAD, rect.x0+rect.width+10, rect.y0+5)
        blocks = page.get_text("blocks", clip=search) or []
        text = " ".join(b[4] for b in blocks if len(b)>=5 and isinstance(b[4], str))
        return text.strip()
    except Exception:
        return ""

def _infer_field_class(name: str, alt: str, label: str) -> str:
    hay = " ".join(filter(None, [name or "", alt or "", label or ""])).lower()
    for klass, pat in FIELD_CLASS_PATTERNS:
        if re.search(pat, hay): return klass
    return "text"
# ---------- layout-aware signature & witness ----------
def _estimate_text_signatures(pdf_stream: io.BytesIO, text: str) -> int:
    try:
        doc = _open_doc(pdf_stream)
    except Exception:
        return min(2, len(re.findall(r"\bsignature\b", text, flags=re.I)))
    hits = 0
    for page in doc:
        blocks = page.get_text("blocks") or []
        sig_blocks = []
        for b in blocks:
            if len(b)>=5 and isinstance(b[4],str) and re.search(r"\bsignature\b", b[4], flags=re.I):
                sig_blocks.append((fitz.Rect(b[0],b[1],b[2],b[3]), b[4]))
        if not sig_blocks: continue
        drawings = page.get_drawings() or []
        horiz = []
        for d in drawings:
            for it in d.get("items", []):
                if it[0] == "l":
                    (x0,y0),(x1,y1) = it[1], it[2]
                    if abs(y1-y0)<1.0 and abs(x1-x0)>60: horiz.append((x0,y0,x1,y1))
        page_counted = 0
        for rect, txt in sig_blocks:
            band = fitz.Rect(rect.x0-10, rect.y1-6, rect.x1+200, rect.y1+18)
            close_line = any((band.y0-6 <= y0 <= band.y1+6) and not (x1 < band.x0 or x0 > band.x1)
                             for x0,y0,x1,y1 in horiz)
            has_underline = bool(re.search(r"_{5,}|_{3,}\s*/{0,1}", txt))
            if close_line or has_underline: page_counted += 1
        hits += min(page_counted, 2)
    doc.close()
    return min(hits, 5)

def _estimate_witness_signatures(pdf_stream: io.BytesIO, text: str) -> int:
    try:
        doc = _open_doc(pdf_stream)
    except Exception:
        return min(2, len(re.findall(r"\bwitness\b", text, flags=re.I)))
    hits = 0
    for page in doc:
        blocks = page.get_text("blocks") or []
        witness_blocks = []
        for b in blocks:
            if len(b)>=5 and isinstance(b[4],str) and re.search(r"\bwitness\b", b[4], flags=re.I):
                witness_blocks.append((fitz.Rect(b[0],b[1],b[2],b[3]), b[4]))
        drawings = page.get_drawings() or []
        horiz = []
        for d in drawings:
            for it in d.get("items", []):
                if it[0] == "l":
                    (x0,y0),(x1,y1) = it[1], it[2]
                    if abs(y1-y0)<1.0 and abs(x1-x0)>60: horiz.append((x0,y0,x1,y1))
        page_counted = 0
        for rect, _ in witness_blocks:
            band = fitz.Rect(rect.x0-10, rect.y1-6, rect.x1+200, rect.y1+18)
            close_line = any((band.y0-6 <= y0 <= band.y1+6) and not (x1 < band.x0 or x0 > band.x1)
                             for x0,y0,x1,y1 in horiz)
            if close_line: page_counted += 1
        hits += min(page_counted, 2)
    doc.close()
    return min(hits, 4)

def analyze_signatures(pdf_stream: io.BytesIO, text: str) -> dict:
    sig_widgets = 0
    try:
        doc = _open_doc(pdf_stream)
        for page in doc:
            for w in (page.widgets() or []):
                if getattr(w,"field_type",None) == fitz.PDF_WIDGET_TYPE_SIGNATURE or getattr(w,"is_signature",False):
                    sig_widgets += 1
        doc.close()
    except Exception: pass
    dig_sigs, has_ts = 0, False
    if _HAS_PYHANKO:
        try:
            pdf_stream.seek(0); rdr = PdfFileReader(pdf_stream)
            sigs = list(gather_signatures(rdr)); dig_sigs = len(sigs)
            for s in sigs:
                if getattr(s,"timestamp",None): has_ts = True; break
        except Exception as e:
            log.warning(f"pyHanko read_signatures failed: {e}")
    text_fb = 0
    if (sig_widgets + dig_sigs) == 0:
        text_fb = _estimate_text_signatures(pdf_stream, text)
    witness = _estimate_witness_signatures(pdf_stream, text)
    notarized_kw = bool(re.search("|".join(NOTARY_PATTERNS), text))
    total = sig_widgets + dig_sigs + text_fb
    return {
        "signature_count": total,
        "witness_signature_count": witness,
        "conditional_signature_count": sum(len(re.findall(p,text)) for p in [r"if.*sign",r"when.*sign",r"unless.*sign"]),
        "notarized": "Yes" if (has_ts or notarized_kw) else "No",
        "signature_debug": {"widgets": sig_widgets, "digital": dig_sigs, "fallback_text_layout": text_fb}
    }

# ---------- entity/title, pii, attachments ----------
def extract_entity_name_financial(text: str, url: str) -> str:
    domains = {
        "fidelity":"Fidelity Investments","vanguard":"Vanguard","schwab":"Charles Schwab",
        "tdameritrade":"TD Ameritrade","morganstanley":"Morgan Stanley",
        "bofa":"Bank of America","bankofamerica":"Bank of America",
        "wellsfargo":"Wells Fargo","chase":"JPMorgan Chase",
        "usbank":"U.S. Bank","pnc":"PNC",
        "cigna":"Cigna","aetna":"Aetna","uhc":"UnitedHealthcare",
        "gsa.gov":"GSA","uscis.gov":"USCIS","irs.gov":"IRS","ssa.gov":"SSA",
    }
    lower = (url or "").lower()
    for k,v in domains.items():
        if k in lower: return v
    for k,v in domains.items():
        if k in (text or ""): return v
    return "Unknown Entity"

def extract_title(meta: dict, text: str) -> str:
    if meta and meta.get("title"): return meta["title"]
    for line in (text or "").splitlines():
        if len(line.strip())>5: return line.strip()[:120]
    return "Unknown Form"

def detect_pii(text: str) -> dict:
    out = {k: False for k in PII_PATTERNS}
    for k, pat in PII_PATTERNS.items():
        if re.search(pat, text, re.I): out[k] = True
    out["any_pii"] = any(out.values())
    return out

def detect_attachment_requirements(text: str) -> list:
    hits = []
    for pat in ATTACHMENT_HINTS:
        if re.search(pat, text, re.I): hits.append(pat)
    return sorted(set(hits))
# ---------- third-party roles ----------
def detect_third_parties(text: str) -> dict:
    roles, ev = [], []
    if not text:
        return {"roles": roles, "evidence": ev}
    low = text.lower()
    for role, pat in THIRD_PARTY_PATTERNS.items():
        m = re.search(pat, low, flags=re.I)
        if m:
            roles.append(role)
            s = max(0, m.start()-40); e = min(len(text), m.end()+40)
            ev.append(text[s:e].strip())
    # de-dupe, drop core signer types
    uniq, seen = [], set()
    for r in roles:
        if r not in CORE_SIGNER_TERMS and r not in seen:
            uniq.append(r); seen.add(r)
    return {"roles": uniq, "evidence": ev[:6]}

# ---------- host vs issuer (config-aware) ----------
def host_domain_info(url: str, entity_name: str, text: str, meta: dict | None, brand_map: dict) -> dict:
    from urllib.parse import urlparse
    host = ""
    try: host = (urlparse(url).netloc or "").lower()
    except Exception: host = ""
    # eTLD+1
    if _HAS_TLDEXTRACT and host:
        ext = tldextract.extract(host)
        host_root = f"{ext.domain}.{ext.suffix}" if ext.suffix else host
    else:
        parts = host.split("."); host_root = ".".join(parts[-2:]) if len(parts)>=2 else host

    ROOT_TO_BRAND = {}
    for brand, doms in brand_map.items():
        for d in doms:
            ROOT_TO_BRAND[d] = brand
    KNOWN_CDNS = ("blob.core.windows.net","azureedge.net","cloudfront.net","akamai","fastly","cdn.")

    issuer = (entity_name or "").strip()
    brand_text_hits, brand_meta_hits = [], []
    if not issuer or issuer=="Unknown Entity":
        lowered = (text or "").lower()
        for brand in brand_map.keys():
            if brand.split()[0].lower() in lowered:
                issuer = brand; brand_text_hits.append(brand); break
    try:
        for k,v in (meta or {}).items():
            val = (v or "").lower() if isinstance(v,str) else ""
            for brand in brand_map.keys():
                if brand.split()[0].lower() in val:
                    brand_meta_hits.append(f"{brand}@{k}")
                    if not issuer or issuer=="Unknown Entity":
                        issuer = brand
    except Exception: pass
    if (not issuer or issuer=="Unknown Entity") and host_root in ROOT_TO_BRAND:
        issuer = ROOT_TO_BRAND[host_root]

    issuer_domains = set(d.lower() for d in brand_map.get(issuer, []))
    matched = [d for d in issuer_domains if (d in host) or (d == host_root)]

    confidence, reasons = 0, []
    if matched: confidence += 60; reasons.append(f"host matches issuer ({', '.join(matched)})")
    if host_root in issuer_domains and not matched: confidence += 25; reasons.append(f"host_root matches issuer ({host_root})")
    if brand_text_hits: confidence += 15; reasons.append("brand in PDF text")
    if brand_meta_hits: confidence += 10; reasons.append("brand in PDF metadata")
    if any(k in host for k in KNOWN_CDNS): confidence -= 15; reasons.append("CDN/third-party host")

    gov_brands = {"GSA","USCIS","IRS","SSA"}
    if issuer in gov_brands and (host and ".gov" not in host):
        confidence += 10; reasons.append("issuer .gov on non-.gov host")

    confidence = max(0, min(100, confidence))
    mismatch, reason = False, ""
    if confidence >= 55:
        if not matched:
            mismatch = True; reason = "Host does not match issuer domains."
        if issuer in gov_brands and (host and ".gov" not in host):
            mismatch = True; reason = "Government issuer on non-.gov host."
    if host_root in ROOT_TO_BRAND and ROOT_TO_BRAND[host_root] == issuer:
        mismatch = False; reason = "Host root aligns with issuer."; confidence = max(confidence, 75)

    return {
        "host_domain": host,
        "host_root": host_root,
        "issuer_guess": issuer or "Unknown",
        "issuer_domains_matched": matched,
        "brand_text_hits": brand_text_hits,
        "brand_meta_hits": brand_meta_hits,
        "confidence": confidence,
        "mismatch": mismatch,
        "reason": reason or ("OK" if not mismatch else "Mismatch"),
    }

# ---------- industry/subvertical ----------
INDUSTRY_SET = {"Financial Services","Healthcare","Public Sector"}
SUBVERTICALS = {
    "Financial Services":{"Wealth Management","P&C Insurance","Banking"},
    "Healthcare":{"Payer","Provider","Life Sciences"},
    "Public Sector":{"Federal Government","State & Local","Education","Not-for-Profit"},
}

def classify_industry_subvertical(url: str, text: str, entity_name: str) -> tuple[str,str]:
    low = (text or "").lower()
    from urllib.parse import urlparse
    try: host = urlparse(url).netloc.lower()
    except Exception: host = ""
    fin = any(k in (host+" "+low) for k in ["fidelity","vanguard","schwab","ameritrade","morgan stanley","us bank","wells fargo","chase","pnc","account","beneficiary","ira","401k","brokerage"])
    wealth  = any(k in low for k in ["custodian","advisor","wealth","brokerage","beneficiary","ira","roth","acat","transfer of assets"])
    banking = any(k in low for k in ["ach","routing number","wire","checking","savings","loan","mortgage","account number"])
    pnc_ins = any(k in low for k in ["policy","claim","loss","insured","adjuster","premium","p&c","auto policy"])
    health = any(k in (host+" "+low) for k in ["cigna","aetna","unitedhealth","uhc","hipaa","prior authorization","member id"])
    payer  = any(k in low for k in ["claim","prior authorization","eligibility","member id","edi 837","payer"])
    provider=any(k in low for k in ["provider","npi","superbill","encounter","progress note"])
    lfs    = any(k in low for k in ["informed consent","clinical trial","irb","sponsor","investigational"])
    public = any(k in (host+" "+low) for k in [".gov","gsa","uscis","irs","ssa","state of","city of","county of","school district"])
    federal= any(k in (host+" "+low) for k in ["gsa",".gov","irs","ssa","uscis","va.gov","dot.gov"]) or "federal" in low
    sled   = any(k in low for k in ["state of","county","city of","municipal","township","dmv","permit","licensure"]) or any(t in host for t in ["wa.gov","ca.gov","az.gov","ny.gov"])
    edu    = any(k in low for k in ["school","university","college","district","k-12","education"])
    nfp    = any(k in low for k in ["501(c)","nonprofit","not-for-profit","charitable"])
    industry, sub = None, None
    if fin:
        industry = "Financial Services"
        sub = "Wealth Management" if wealth else ("P&C Insurance" if pnc_ins else ("Banking" if banking else "Wealth Management"))
    elif health:
        industry = "Healthcare"
        sub = "Payer" if payer else ("Provider" if provider else ("Life Sciences" if lfs else "Payer"))
    elif public:
        industry = "Public Sector"
        sub = "Federal Government" if federal else ("Education" if edu else ("State & Local" if sled else ("Not-for-Profit" if nfp else "State & Local")))
    if industry not in INDUSTRY_SET: return "", ""
    if sub not in SUBVERTICALS[industry]: sub = next(iter(SUBVERTICALS[industry]))
    return industry, sub

# ---------- NIGO checks & score ----------
def nigo_design_checks(pdf_stream: io.BytesIO) -> list:
    findings = []
    try:
        pdf_stream.seek(0)
        doc = fitz.open(stream=pdf_stream.read(), filetype="pdf")
        for i, page in enumerate(doc, start=1):
            widgets = page.widgets() or []
            for w in widgets:
                fname = (getattr(w,"field_name","") or "").strip()
                alt   = (getattr(w,"tooltip","") or "").strip()
                label = _label_near_widget(doc, page, w)
                fclass= _infer_field_class(fname, alt, label)
                is_req= bool(getattr(w,"is_required",False))
                has_actions = False
                try:
                    acts = w.get_actions()
                    if acts: has_actions = True
                except Exception: pass
                page_has_js = False
                try:
                    if page.get_actions() or page.get_javascript(): page_has_js = True
                except Exception: pass
                expected_mask = fclass in {"ssn","tin","ein","dob","date","phone","email","zip","state","routing","account","amount"}
                expected_required = fclass in {"signature","dob","ssn","email","phone","zip","state","routing","account","amount"}
                if expected_required and not is_req:
                    findings.append({"rule_id":"REQ-001","severity":"high","page":i,"field_name":fname or alt or "(unnamed)","field_class":fclass,"issue":"Field likely should be required but isn't.","evidence":f"Label='{label[:120]}' name='{fname}'"})
                if expected_mask and not (has_actions or page_has_js):
                    findings.append({"rule_id":"FMT-001","severity":"medium","page":i,"field_name":fname or alt or "(unnamed)","field_class":fclass,"issue":"No input mask/validation detected for a high-risk field.","evidence":f"Class={fclass}; no field/page actions found."})
                if fclass=="signature" and not re.search(r"\b(date)\b",(label or "").lower()):
                    findings.append({"rule_id":"SIG-002","severity":"low","page":i,"field_name":fname or "(signature)","field_class":fclass,"issue":"Signature likely needs an adjacent Date field.","evidence":f"Nearby label='{label[:120]}'"})
                if re.search(r"\b(beneficiary|dependent)\b",(label+" "+alt+" "+fname).lower()) and not (page_has_js or has_actions):
                    findings.append({"rule_id":"COND-003","severity":"medium","page":i,"field_name":fname or "(beneficiary)","field_class":fclass,"issue":"Conditional area lacks visible logic; consider requiring SSN/DOB masks.","evidence":f"Label='{label[:120]}'"})
        doc.close()
    except Exception as e:
        findings.append({"rule_id":"SYS-ERR","severity":"info","page":None,"field_name":"","field_class":"","issue":"Analyzer error during NIGO checks.","evidence":str(e)})
    return findings

def calculate_nigo_score(nigo_risks: list, pii_flags: dict) -> int:
    if not isinstance(nigo_risks, list): nigo_risks = []
    score = 0; high_mask_req = 0
    for r in nigo_risks:
        sev = (r.get("severity") or "").lower()
        rule= (r.get("rule_id") or "")
        fcl = (r.get("field_class") or "").lower()
        score += SEVERITY_WEIGHTS.get(sev,0) + RULE_WEIGHTS.get(rule,0) + (5 if fcl in HIGH_RISK_FIELDS else 0)
        if rule in ("FMT-001","REQ-001") and fcl in HIGH_RISK_FIELDS:
            high_mask_req += 1
    if (pii_flags or {}).get("any_pii") and high_mask_req > 0:
        score += 10
    return int(min(score, 100))
# ---------- special req summary ----------
def summarize_special_requirements(result: dict) -> list:
    bullets = []
    sig = result.get("signature_analysis",{}) or {}
    if sig.get("notarized") == "Yes": bullets.append("Requires notarization")
    if sig.get("witness_signature_count",0) > 0: bullets.append("Requires witness signature")
    if result.get("signatures",0) > 0 or sig.get("signature_count",0) > 0:
        bullets.append(f"{max(result.get('signatures',0), sig.get('signature_count',0))} signature field(s)")
    if result.get("attachment_count",0) > 0 or (result.get("attachment_requirements") or []):
        bullets.append("Requires supporting attachments")
    if result.get("conditional_logic")=="Yes" or result.get("multistep_logic_hint"):
        bullets.append("Conditional/JavaScript logic present")
    if (result.get("pii_fields") or {}).get("any_pii"): bullets.append("Collects sensitive PII")
    if result.get("radio_groups",0) >= 2: bullets.append("Multiple radio groups (branching choices)")
    if result.get("page_count",0) >= 8: bullets.append("Long form (8+ pages)")
    if result.get("deadlines"): bullets.append("Mentions submission timing/deadlines")
    if result.get("dependencies"): bullets.append("References other required forms")
    dm = result.get("host_domain_check") or {}
    if dm.get("mismatch"): bullets.append("Hosted on domain different from issuer")
    tpro = result.get("third_party_roles") or []
    if tpro: bullets.append("Involves third party: " + ", ".join(tpro))
    out, seen = [], set()
    for b in bullets:
        if b not in seen:
            out.append(b); seen.add(b)
    return out

# ---------- complexity scoring (re-weighted) ----------
def calculate_complexity(text: str, fields: dict, pages: int, sigs: dict, extra: dict=None) -> int:
    extra = extra or {}; score = 0.0
    score += min(pages*2, 10)                      # de-emphasize length
    score += min(fields.get("total",0)*0.3, 15)    # de-emphasize fields
    if sigs.get("signature_count",0)>0: score += 4
    if sigs.get("witness_signature_count",0)>0: score += 10
    if sigs.get("notarized")=="Yes": score += 12
    if "attach" in (text or ""): score += 3
    if extra.get("attachments_req"): score += min(8, 2+2*len(extra["attachments_req"]))
    if extra.get("has_js"): score += 4
    if extra.get("has_js") and extra.get("radio_groups",0)>=2: score += 3
    roles = extra.get("roles") or []; score += min(18, 3*len(set(roles)))
    # 3rd-party coordination
    tpr = (extra or {}).get("third_party_count", 0)
    if tpr >= 3: score += 12
    elif tpr == 2: score += 8
    elif tpr == 1: score += 4
    tpro = (extra or {}).get("third_party_roles") or []
    if any(r in tpro for r in ["Physician","Attorney","Financial Advisor"]): score += 4
    # PII light (heavy in NIGO)
    pii = extra.get("pii") or {}
    for key,wt in [("ssn",3),("dob",2),("acct",3),("routing",3),("email",1),("phone",1),("addr",1),("tin",2),("ein",2)]:
        if pii.get(key): score += wt
    # branch/layout
    rg = extra.get("radio_groups",0)
    if rg>=1: score += min(6, 2+1.0*rg)
    gfx = extra.get("gfx") or {}
    img_pp = gfx.get("images_per_page",0.0); draw_pp = gfx.get("drawings_per_page",0.0)
    if draw_pp>=30: score += 4
    elif draw_pp>=15: score += 3
    elif draw_pp>=5: score += 1
    if img_pp>=2.0: score += 3
    elif img_pp>=1.0: score += 1
    if extra.get("xfa_hint"): score += 4
    if extra.get("deadlines",0)>=1: score += 2
    deps = extra.get("dependencies",0)
    if deps>=2: score += 3
    elif deps==1: score += 1
    if extra.get("domain_mismatch"): score += 2
    return int(min(score, 100))

# ---------- analyze one ----------
def analyze_one(item: str, brand_map: dict) -> dict:
    rid = str(uuid.uuid4())
    try:
        if re.match(r"^https?://", item, re.I): pdf = _download(item); url = item
        else:
            with open(item,"rb") as f: data = f.read()
            pdf = io.BytesIO(data); url = os.path.abspath(item)

        text = extract_text(pdf)
        doc  = _open_doc(pdf); meta = doc.metadata or {}; pages = len(doc); doc.close()

        fields   = count_fields(pdf)
        sigs     = analyze_signatures(pdf, text)
        attach_c = count_attachments(pdf)
        has_js   = detect_js(pdf)

        pii      = detect_pii(text)
        attach_r = detect_attachment_requirements(text)
        roles    = detect_roles(text)
        radios   = count_radio_groups(pdf)
        gfx      = page_graphics_stats(pdf)
        xfa      = xfa_like_hint(text, meta)
        nigo_r   = nigo_design_checks(pdf)

        deps     = detect_dependencies(text)
        dls      = detect_deadlines(text)
        entity   = extract_entity_name_financial(text, url)
        domain   = host_domain_info(url, entity, text, meta, brand_map)
        industry, subvertical = classify_industry_subvertical(url, text, entity)

        # ---- Third-party roles
        tp = detect_third_parties(text)
        third_party_roles = tp["roles"]
        third_party_evidence = tp["evidence"]

        # If signatures present but roles empty -> add "Unspecified Signer" + NIGO ROLE-001
        missing_role_findings = []
        if sigs.get("signature_count",0) > 0 and not roles:
            roles = ["Unspecified Signer"]
            missing_role_findings.append({
                "rule_id":"ROLE-001","severity":"medium","page":None,
                "field_name":"","field_class":"signature",
                "issue":"Signature line(s) without role attribution (e.g., Applicant, Co-owner, Notary).",
                "evidence":f"Detected {sigs.get('signature_count',0)} signature(s) with no labeled role."
            })
        if missing_role_findings: nigo_r.extend(missing_role_findings)

        # NIGO: third-party coordination risk
        if third_party_roles:
            nigo_r.append({
                "rule_id":"THRD-001","severity":"medium","page":None,
                "field_name":"","field_class":"third_party",
                "issue":"Third-party involvement requires coordination (scheduling, credential validation).",
                "evidence":f"Detected third-party role(s): {', '.join(third_party_roles)}"
            })

        nigo_score = calculate_nigo_score(nigo_r, pii)

        res = {
            "url": url,
            "analysis_id": rid,
            "timestamp": datetime.now().isoformat(),
            "entity_name": entity,
            "form_title": extract_title(meta, text),
            "page_count": pages,
            "field_count": fields.get("total",0),
            "text_fields": fields.get("text_fields",0),
            "checkboxes": fields.get("checkboxes",0),
            "dropdowns": fields.get("dropdowns",0),
            "radio_groups": radios,
            "signatures": fields.get("signatures",0),
            "attachment_count": attach_c,
            "attachment_requirements": attach_r,
            "conditional_logic": has_js,
            "multistep_logic_hint": (has_js == "Yes" and radios >= 2),
            "signature_analysis": sigs,
            "roles_required": roles,
            "third_party_roles": third_party_roles,
            "third_party_evidence": third_party_evidence,
            "pii_fields": pii,
            "images_per_page": gfx.get("images_per_page",0.0),
            "drawings_per_page": gfx.get("drawings_per_page",0.0),
            "text_density": gfx.get("text_density",0.0),
            "xfa_like": xfa,
            "nigo_risks": nigo_r,
            "nigo_score": nigo_score,  # kept for CSV/debug; not shown in table
            "dependencies": deps,
            "deadlines": dls,
            "host_domain_check": domain,
            "industry": industry,
            "subvertical": subvertical,
            "complexity_score": calculate_complexity(
                text, fields, pages, sigs,
                extra=dict(
                    pii=pii, roles=roles, attachments_req=attach_r,
                    radio_groups=radios, gfx=gfx, xfa_hint=xfa,
                    has_js=(has_js=="Yes"), deadlines=len(dls), dependencies=len(deps),
                    domain_mismatch=bool(domain.get("mismatch")),
                    third_party_count=len(third_party_roles),
                    third_party_roles=third_party_roles,
                )
            ),
            "status": "success",
        }
        res["special_requirements_summary"] = summarize_special_requirements(res)
        return res
    except Exception as e:
        log.error(f"Analyze failed for {item}: {e}")
        return {"url": item, "status":"error", "error": str(e), "analysis_id": rid}
# ---------- batch I/O ----------
def load_inputs(path: str) -> list:
    items = []
    with open(path,"r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            items.append(line)
    return items

def write_csv(csv_path: str, results: list):
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    with open(csv_path,"w",newline="") as f:
        w = csv.writer(f)
        w.writerow(["form_title","url","page","field_name","field_class","rule_id","severity","issue","evidence","nigo_score"])
        for r in results:
            risks = r.get("nigo_risks",[]) or []
            if not risks:
                w.writerow([r.get("form_title"), r.get("url"), "", "", "", "", "", "NO_NIGO", "", r.get("nigo_score",0)])
            else:
                for g in risks:
                    w.writerow([
                        r.get("form_title"), r.get("url"),
                        g.get("page",""), g.get("field_name",""),
                        g.get("field_class",""), g.get("rule_id",""),
                        g.get("severity",""), g.get("issue",""),
                        g.get("evidence","")
                    ])

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", help="Text file with one URL or file path per line")
    ap.add_argument("--url", help="Analyze a single URL or file path (overrides --inputs)")
    ap.add_argument("--out", default="data/analyses.json")
    ap.add_argument("--csv", default=None, help="Optional CSV path to write NIGO findings")
    ap.add_argument("--brands", default="config/brands.yml", help="Optional YAML with issuer->domains")
    args = ap.parse_args()

    # Load brand config
    brands_path = Path(args.brands)
    brand_map   = load_brand_config(brands_path)

    # Inputs
    items = [args.url] if args.url else (load_inputs(args.inputs) if args.inputs else None)
    if not items:
        raise SystemExit("Provide --url or --inputs")

    log.info(f"Loaded {len(items)} items")
    results = []
    for it in items:
        results.append(analyze_one(it, brand_map))
        time.sleep(0.2)  # polite spacing

    out = {"generated_at": datetime.now().isoformat(), "count": len(results), "results": results}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out,"w") as f: json.dump(out, f, indent=2)
    log.info(f"Wrote {args.out}")

    if args.csv:
        flat = results if isinstance(results, list) else out.get("results",[])
        write_csv(args.csv, flat)
        log.info(f"Wrote {args.csv}")

if __name__ == "__main__":
    main()
