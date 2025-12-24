import re
import hashlib
from typing import Dict, List, Pattern, Optional, TypedDict
import base64

# --- Verhoeff Algorithm for Aadhaar Validation ---
VERHOEFF_MUL_P = ((0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5), (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7), (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1), (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3), (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0))
VERHOEFF_PERM_P = ((0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4), (5, 8, 0, 3, 7, 9, 6, 1, 4, 2), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7), (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1), (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8))

def verhoeff_validate(num_str: str) -> bool:
    try:
        c = 0
        for i, item in enumerate(reversed(num_str)): c = VERHOEFF_MUL_P[c][VERHOEFF_PERM_P[i % 8][int(item)]]
        return c == 0
    except (ValueError, IndexError): return False

XOR_KEY = "YourSecretKeyForPIIDetection"
def encrypt_decrypt(text: str, key: str) -> str: return "".join(chr(ord(c) ^ ord(k)) for c, k in zip(text, key * (len(text) // len(key) + 1)))

class EmailPseudonymizer:
    def __init__(self): self.mapping: Dict[str, str] = {}; self.counter: int = 1
    def pseudonymize(self, local_part: str) -> str:
        if local_part not in self.mapping: self.mapping[local_part] = f"user{self.counter}"; self.counter += 1
        return self.mapping[local_part]

class DetectionCounts(TypedDict, total=False):
    aadhaar: int; pan: int; credit_card: int; email: int; passport: int;
    driving_license: int; phone: int; person: int

AADHAAR_PATTERN = re.compile(r"\b(\d{4}[\s-]?){2}\d{4}\b")
PAN_PATTERN = re.compile(r"\b([A-Z]{5}\d{4}[A-Z])\b")
CREDIT_CARD_PATTERN = re.compile(r"\b(\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})\b")
EMAIL_PATTERN = re.compile(r"\b([A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,}))\b")
PASSPORT_PATTERN = re.compile(r"\b([A-Z]\d{7})\b")
DRIVING_LICENSE_PATTERN = re.compile(r"\b(([A-Z]{2})-?(\d{13}))\b")
PHONE_PATTERN = re.compile(r"\b(?:\+91[\s-]?)?([6-9]\d{9})\b")
PERSON_PATTERN = re.compile(r"\b([A-Z][a-z]{1,}(?: [A-Z][a-z]{1,})*)\b")

PATTERN_PRESETS = {"Indian (Default)": {"aadhaar": AADHAAR_PATTERN.pattern, "pan": PAN_PATTERN.pattern, "credit_card": CREDIT_CARD_PATTERN.pattern, "email": EMAIL_PATTERN.pattern, "passport": PASSPORT_PATTERN.pattern, "driving_license": DRIVING_LICENSE_PATTERN.pattern, "phone": PHONE_PATTERN.pattern, "person": PERSON_PATTERN.pattern}, "Custom": {"aadhaar": "", "pan": "", "credit_card": "", "email": "", "passport": "", "driving_license": "", "phone": "", "person": ""}}

class MaskConfig(TypedDict):
    enabled: bool; strategy: str; char: str

def _apply_mask(m: re.Match[str], strategy: str, mask_char: str, pii_type: str, partial_mask_func: callable) -> str:
    original_text = m.group(0)
    if strategy == "partial": return partial_mask_func(m)
    if strategy == "full": return mask_char * len(original_text)
    if strategy == "hash": return hashlib.sha256(original_text.encode()).hexdigest()
    if strategy == "encrypt":
        encrypted = encrypt_decrypt(original_text, XOR_KEY)
        return base64.b64encode(encrypted.encode()).decode()
    if strategy == "redact": return f"[{pii_type.upper()}_REDACTED]"
    return original_text

def luhn_checksum_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]; total = 0
    if not 13 <= len(digits) <= 19: return False
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity: d *= 2
        if d > 9: d -= 9
        total += d
    return total % 10 == 0

def mask_aadhaar(text: str, pattern: Optional[Pattern[str]] = None, **kwargs) -> tuple[str, int]:
    count = 0
    def repl(m: re.Match[str]) -> str:
        nonlocal count
        raw = re.sub(r'[^0-9]', '', m.group(0))
        if len(raw) != 12 or not verhoeff_validate(raw): return m.group(0)
        count += 1
        def partial(match: re.Match[str]) -> str: return f"{raw[:4]}-{kwargs.get('char', '*')*4}-{raw[8:]}"
        return _apply_mask(m, kwargs.get("strategy", "partial"), kwargs.get("char", "*"), "Aadhaar", partial)
    p = pattern or AADHAAR_PATTERN
    masked_text = p.sub(repl, text)
    return masked_text, count

def anonymize_pan(text: str, pattern: Optional[Pattern[str]] = None, **kwargs) -> tuple[str, int]:
    def repl(m: re.Match[str]) -> str:
        def partial(match: re.Match[str]) -> str:
            raw = match.group(0)
            return f"{raw[:3]}{kwargs.get('char', '*')*6}{raw[-1]}"
        return _apply_mask(m, kwargs.get("strategy", "partial"), kwargs.get("char", "*"), "PAN", partial)
    p = pattern or PAN_PATTERN
    return p.subn(repl, text)

def mask_credit_cards(text: str, pattern: Optional[Pattern[str]] = None, **kwargs) -> tuple[str, int]:
    count = 0
    def repl(m: re.Match[str]) -> str:
        nonlocal count
        raw = re.sub(r"[^\d]", "", m.group(0))
        if not luhn_checksum_ok(raw): return m.group(0)
        count += 1
        def partial(_) -> str: return f"{kwargs.get('char', '*')*4}-{kwargs.get('char', '*')*4}-{kwargs.get('char', '*')*4}-{raw[-4:]}"
        return _apply_mask(m, kwargs.get("strategy", "partial"), kwargs.get("char", "*"), "Credit Card", partial)
    p = pattern or CREDIT_CARD_PATTERN
    return p.sub(repl, text), count

def pseudo_email(text: str, pattern: Optional[Pattern[str]] = None, **kwargs) -> tuple[str, int]:
    def repl(m: re.Match[str]) -> str:
        def partial(match: re.Match[str]) -> str:
            full_email = match.group(1)
            if '@' not in full_email: return f"Invalid Email Match: {full_email}"
            local, domain = full_email.rsplit('@', 1)
            context = kwargs.get("context")
            if context and isinstance(context, dict):
                anonymizer = context.setdefault('email_anonymizer', EmailPseudonymizer())
                return f"{anonymizer.pseudonymize(local)}@{domain}"
            return f"maskeduser@{domain}"
        return _apply_mask(m, kwargs.get("strategy", "partial"), kwargs.get("char", "*"), "Email", partial)
    p = pattern or EMAIL_PATTERN
    return p.subn(repl, text)

def mask_passport(text: str, pattern: Optional[Pattern[str]] = None, **kwargs) -> tuple[str, int]:
    def repl(m: re.Match[str]) -> str:
        def partial(match: re.Match[str]) -> str:
            raw = match.group(0)
            return f"{raw[0]}{kwargs.get('char', '*')*(len(raw)-1)}"
        return _apply_mask(m, kwargs.get("strategy", "partial"), kwargs.get("char", "*"), "Passport", partial)
    p = pattern or PASSPORT_PATTERN
    return p.subn(repl, text)

def mask_driving_license(text: str, pattern: Optional[Pattern[str]] = None, **kwargs) -> tuple[str, int]:
    def repl(m: re.Match[str]) -> str:
        def partial(match: re.Match[str]) -> str:
            state_code = match.group(2) or "" # Group 2 is the state code in the new regex
            return f"{state_code}{kwargs.get('char', '*')*14}" if state_code else match.group(0)
        return _apply_mask(m, kwargs.get("strategy", "partial"), kwargs.get("char", "*"), "Driving License", partial)
    p = pattern or DRIVING_LICENSE_PATTERN
    return p.subn(repl, text)

def mask_phone(text: str, pattern: Optional[Pattern[str]] = None, **kwargs) -> tuple[str, int]:
    def repl(m: re.Match[str]) -> str:
        def partial(match: re.Match[str]) -> str:
            raw = re.sub(r'[^\d]', '', match.group(0))[-10:] # Get last 10 digits
            return f"{raw[:2]}{kwargs.get('char', '*')*6}{raw[-2:]}"
        return _apply_mask(m, kwargs.get("strategy", "partial"), kwargs.get("char", "*"), "Phone", partial)
    p = pattern or PHONE_PATTERN
    return p.subn(repl, text)

def mask_person(text: str, pattern: Optional[Pattern[str]] = None, **kwargs) -> tuple[str, int]:
    def repl(m: re.Match[str]) -> str:
        def partial(match: re.Match[str]) -> str:
            # Updated logic to mask all but the first letter of each word in a name
            parts = match.group(0).split()
            masked_parts = [p[0] + kwargs.get('char', '*') * (len(p) - 1) for p in parts]
            return " ".join(masked_parts)
        return _apply_mask(m, kwargs.get("strategy", "partial"), kwargs.get("char", "*"), "Person", partial)
    p = pattern or PERSON_PATTERN
    return p.subn(repl, text)

PII_HANDLERS = {"aadhaar": mask_aadhaar, "pan": anonymize_pan, "credit_card": mask_credit_cards, "email": pseudo_email, "passport": mask_passport, "driving_license": mask_driving_license, "phone": mask_phone, "person": mask_person}

def get_preset_patterns(preset_name: str) -> Dict[str, str]: return PATTERN_PRESETS.get(preset_name, PATTERN_PRESETS["Indian (Default)"])
def get_available_presets() -> List[str]: return list(PATTERN_PRESETS.keys())

def process_text(text: str, patterns: Optional[Dict] = None, mask_configs: Optional[Dict] = None, context: Optional[Dict] = None) -> tuple[str, Dict]:
    counts: Dict = {key: 0 for key in PII_HANDLERS}
    for key, handler in PII_HANDLERS.items():
        # Check if the 'enabled' flag is True for this PII type
        config = (mask_configs or {}).get(key, {"enabled": False})
        if config.get("enabled"):
            config['context'] = context; pattern_override = (patterns or {}).get(key)
            text, count = handler(text, pattern=pattern_override, **config)
            counts[key] += count
    return text, counts

def detect_and_deidentify_record(row: List[str], patterns: Optional[Dict] = None, mask_configs: Optional[Dict] = None, context: Optional[Dict] = None) -> tuple[List[str], Dict]:
    out_row, total_counts = [], {key: 0 for key in PII_HANDLERS}
    for cell in row:
        masked_cell, cell_counts = process_text(cell or "", patterns, mask_configs, context=context)
        out_row.append(masked_cell)
        for key in total_counts: total_counts[key] += cell_counts.get(key, 0)
    return out_row, total_counts
