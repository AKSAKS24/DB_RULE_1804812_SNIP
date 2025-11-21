from fastapi import FastAPI, Body
from pydantic import BaseModel
from typing import List, Optional
import re
import json

app = FastAPI(title="ABAP MB Transaction Remediator (SAP Note 1804812)")

# ------------------------------------------------------------
# REGEX
# ------------------------------------------------------------
OBSOLETE_MB_TXNS = [
    "MB01", "MB02", "MB03", "MB04", "MB05", "ΜΒΘΑ", "MB11",
    "MB1A", "MB18", "MBC", "MB31", "MBNL", "MBRL", "MBSF",
    "MBSL", "MBST", "MBSU"
]

MB_TXN_RE = re.compile(
    rf"""
    (?P<full>
        (?P<stmt>CALL\s+TRANSACTION|SUBMIT)
        \s+['"]?(?P<txn>{'|'.join(OBSOLETE_MB_TXNS)})['"]?
        \s*\.?
    )
    """,
    re.IGNORECASE | re.VERBOSE
)

# ------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------
def extract_line(text: str, pos: int) -> str:
    s = text.rfind("\n", 0, pos) + 1
    e = text.find("\n", pos)
    if e == -1:
        e = len(text)
    return text[s:e].strip()

def get_line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1

def suggest(stmt: str) -> str:
    return "SUBMIT MIGO." if stmt.upper().startswith("SUBMIT") else "CALL TRANSACTION 'MIGO'."

def find_txn_usage(src: str):
    hits = []
    for m in MB_TXN_RE.finditer(src):
        hits.append({
            "span": m.span("full"),
            "stmt": m.group("stmt"),
            "txn": m.group("txn"),
            "line": extract_line(src, m.start()),
            "suggestion": suggest(m.group("stmt"))
        })
    return hits

# ------------------------------------------------------------
# MODELS (REFERENCE FORMAT)
# ------------------------------------------------------------
class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None
    severity: Optional[str] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None

# ------------------------------------------------------------
# CORE
# ------------------------------------------------------------
def scan_unit(unit: Unit):
    src = unit.code or ""
    findings = []

    for m in find_txn_usage(src):
        findings.append(Finding(
            prog_name=unit.pgm_name,
            incl_name=unit.inc_name,
            types=unit.type,
            blockname=unit.name,
            starting_line=get_line(src, m["span"][0]),
            ending_line=get_line(src, m["span"][0]),
            issues_type="MB_Obsolete_Transaction",
            severity="error",
            message=f"Obsolete MB transaction '{m['txn']}' used.",
            suggestion=m["suggestion"],
            snippet=m["line"]
        ))

    out = unit.model_dump()
    out["findings"] = [f.model_dump() for f in findings]
    return out

# ------------------------------------------------------------
# ENDPOINTS (ALWAYS TWO — TYPE A)
# ------------------------------------------------------------
@app.post("/remediate-array")
async def remediate_mb_array(units: List[Unit] = Body(...)):
    res = []
    for u in units:
        scanned = scan_unit(u)
        if scanned["findings"]:
            res.append(scanned)
    return res

@app.post("/remediate")
async def remediate_mb(unit: Unit = Body(...)):
    return scan_unit(unit)
