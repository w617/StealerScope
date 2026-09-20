"""Explainable format detection. Format confidence is not malware attribution."""
import codecs
import csv
import io
import os
import re

SAMPLE_BYTES = 65536
LABELS = {"url": "url", "host": "url", "user": "username", "username": "username",
          "login": "username", "pass": "password", "password": "password",
          "soft": "soft", "browser": "soft"}
SYSTEM_KEYS = {"host", "hostname", "computer name", "os", "operating system", "hwid",
               "username", "user name", "ip", "ip address", "country", "machine id"}
LINE_FILES = {"brute.txt": "brute_passwords", "domaindetect.txt": "detected_domains",
              "processes.txt": "processes", "software.txt": "installed_software"}


def text_encoding(prefix):
    if prefix.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return "utf-32"
    if prefix.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return "utf-16"
    return "utf-8-sig"


def family_assessment(evidence):
    candidates = sorted({item["candidate"] for item in evidence})
    return {"status": "ambiguous" if len(candidates) > 1 else "unverified" if candidates else "unknown",
            "family": None, "candidates": candidates,
            "confidence": "low" if len(candidates) == 1 else "none",
            "evidence": evidence,
            "reason": "Explicit log labels are unverified claims, not independently validated family signatures."
            if candidates else "No validated family signature matched. Shared formats and filenames cannot establish a malware family."}


def detect_file(path):
    with open(path, "rb") as stream:
        raw = stream.read(SAMPLE_BYTES + 1)
    truncated = len(raw) > SAMPLE_BYTES
    raw = raw[:SAMPLE_BYTES]
    encoding = text_encoding(raw)
    text = codecs.getincrementaldecoder(encoding)(errors="replace").decode(raw, final=not truncated)
    result = {"format": "unknown", "confidence": "none", "evidence": [],
              "sample_bytes": len(raw), "sample_truncated": truncated, "encoding": encoding,
              "family_assessment": family_assessment([])}
    if "\x00" in text or sum(ord(c) < 32 and c not in "\r\n\t" for c in text) > max(2, len(text) // 100):
        result.update(format="binary", reason="Binary content; no supported text parser.")
        return result
    lines = text.splitlines()
    if truncated:
        lines = lines[:-1]  # Do not classify an incomplete sampled line as a full record.
    claims, fields = [], {}
    for number, line in enumerate(lines, 1):
        claim = re.fullmatch(r"\s*(?:malware(?: family)?|stealer|family)\s*:\s*([A-Za-z][A-Za-z0-9_-]{1,39})(?:\s+v?\d[\w.-]*)?\s*", line, re.I)
        if claim:
            claims.append({"candidate": claim[1].lower(), "source": os.fspath(path),
                           "line": number, "indicator": "explicit_family_label", "strength": "unverified"})
        match = re.match(r"^\s*([^:]{1,40})\s*:", line)
        if match:
            fields.setdefault(match[1].strip().lower(), number)
    result["family_assessment"] = family_assessment(claims)
    candidates = []
    canonical = {LABELS[key] for key in fields if key in LABELS}
    if {"url", "username", "password"}.issubset(canonical):
        candidates.append(("credential_blocks", "high", [{"indicator": "credential_field", "label": key,
                            "line": number} for key, number in fields.items() if key in LABELS]))
    # Delimited credentials require an explicit header; bare colon-separated strings
    # are deliberately not guessed (URLs and passwords can both contain colons).
    header_text = "\n".join(lines)
    for delimiter in (",", "\t", ";"):
        try:
            header = next(csv.reader(io.StringIO(header_text), delimiter=delimiter), [])
        except csv.Error:
            continue
        mapped = [LABELS.get(value.strip().lower()) for value in header]
        if {"url", "username", "password"}.issubset(mapped) and all(mapped.count(k) == 1 for k in ("url", "username", "password")):
            candidates.append(("credential_table", "high", [{"indicator": "credential_table_header", "line": 1}]))
            result["delimiter"] = delimiter
            break
    cookie_lines = []
    for number, line in enumerate(lines, 1):
        if line.startswith("#HttpOnly_"):
            line = line[len("#HttpOnly_"):]
        elif line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) == 7 and parts[1] in ("TRUE", "FALSE") and parts[3] in ("TRUE", "FALSE") and parts[4].isdigit():
            cookie_lines.append(number)
    if cookie_lines:
        candidates.append(("netscape_cookies", "high", [{"indicator": "seven_column_cookie_record", "line": cookie_lines[0]}]))
    system_fields = SYSTEM_KEYS.intersection(fields)
    if len(system_fields) >= 2 and not {"username", "password"}.issubset(canonical):
        candidates.append(("system_key_values", "medium", [{"indicator": "system_field", "label": key,
                           "line": fields[key]} for key in sorted(system_fields)]))
    if len(candidates) > 1:
        result.update(format="ambiguous", candidates=[item[0] for item in candidates],
                      reason="Multiple incompatible formats detected; manual review required.")
        result["evidence"] = [e for item in candidates for e in item[2]]
    elif candidates:
        result["format"], result["confidence"], result["evidence"] = candidates[0]
    else:
        name = os.path.basename(path).lower()
        fallback = ("credential_blocks" if name in ("all passwords.txt", "passwords.txt")
                    else "system_key_values" if name == "system.txt"
                    else "line_list" if name in LINE_FILES else None)
        if fallback:
            result.update(format=fallback, confidence="low", evidence=[{"indicator": "filename_hint", "name": name}])
        else:
            result["reason"] = "No supported content format found in the bounded sample."
    return result
