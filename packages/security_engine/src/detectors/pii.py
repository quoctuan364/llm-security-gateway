import re
from typing import Dict, List, Tuple
from packages.shared.src.models.decision import (
    DetectionCategory,
    DetectionDetail,
)


def luhn_checksum_is_valid(card_number_str: str) -> bool:
    """Validates payment card numbers using the standard Luhn algorithm (mod 10)."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def is_valid_vietnamese_cccd(cccd_str: str) -> bool:
    """
    Validates standard 12-digit Vietnamese Citizen ID (Căn cước công dân).
    Format: PPP G YY RRRRRR
    - PPP: Province code (001 to 096)
    - G: Gender/Century code (0 to 9)
    - YY: Last 2 digits of birth year
    - RRRRRR: 6-digit random number
    """
    if len(cccd_str) != 12 or not cccd_str.isdigit():
        return False
    province_code = int(cccd_str[:3])
    # Valid province range in Vietnam is 001 to 096
    if province_code < 1 or province_code > 96:
        return False
    return True


class PIIDetector:
    """
    High-performance, regex- and algorithmic-based PII & sensitive credential detector.
    Detects Vietnamese Phone Numbers, Vietnamese CCCD, Payment Cards (with Luhn),
    Email addresses, and High-entropy API Keys / Private Tokens.
    """

    # Vietnamese Phone: (+84 or 0) followed by valid mobile prefixes (3x, 5x, 7x, 8x, 9x) and 7 digits
    RE_VN_PHONE = re.compile(r'(?:\+84|0)(?:3[2-9]|5[689]|7[06-9]|8[1-9]|9[0-9])[0-9]{7}\b')

    # Vietnamese 12-digit Citizen ID (CCCD)
    RE_VN_CCCD = re.compile(r'\b[0-9]{12}\b')

    # Payment Card Numbers (Visa, MasterCard, Amex, Discover - 13 to 19 digits)
    RE_PAYMENT_CARD = re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b')

    # Email Addresses
    RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')

    # API Keys & Secrets
    PATTERNS_API_KEYS = [
        ("OPENAI_KEY", re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b'), 0.95),
        ("AWS_KEY", re.compile(r'\b(?:AKIA|ABIA|ACCA)[0-9A-Z]{16}\b'), 0.98),
        ("GITHUB_TOKEN", re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{36,}\b'), 0.98),
        ("BEARER_JWT", re.compile(r'\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b'), 0.85),
        ("PRIVATE_KEY", re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'), 1.0),
    ]

    def scan_and_redact(
        self, text: str, preserve_map: bool = True
    ) -> Tuple[str, List[DetectionDetail], Dict[str, str]]:
        """
        Scans input text for sensitive entities, generates detections, and replaces
        sensitive values with typed redacted placeholders.
        """
        detections: List[DetectionDetail] = []
        redaction_map: Dict[str, str] = {}
        redacted_text = text

        # 1. API Keys & Secrets
        for key_type, pattern, risk in self.PATTERNS_API_KEYS:
            for match in pattern.finditer(text):
                val = match.group(0)
                placeholder = f"[REDACTED_{key_type}_{len(redaction_map) + 1}]"
                redaction_map[placeholder] = val
                redacted_text = redacted_text.replace(val, placeholder)
                detections.append(
                    DetectionDetail(
                        category=DetectionCategory.CREDENTIAL_LEAK,
                        rule_id=f"SECRET_{key_type}",
                        risk_score=risk,
                        description=f"Detected high-entropy API key or private secret ({key_type})",
                        sanitized_evidence=f"{val[:4]}...{val[-3:]}",
                    )
                )

        # 2. Payment Cards (with Luhn check)
        card_candidate_re = re.compile(r'\b(?:\d[ -]?){13,19}\b')
        for match in card_candidate_re.finditer(text):
            raw_match = match.group(0)
            digits_only = re.sub(r'[\s-]', '', raw_match)
            if 13 <= len(digits_only) <= 19 and luhn_checksum_is_valid(digits_only):
                placeholder = f"[REDACTED_PAYMENT_CARD_{len(redaction_map) + 1}]"
                redaction_map[placeholder] = raw_match
                redacted_text = redacted_text.replace(raw_match, placeholder)
                detections.append(
                    DetectionDetail(
                        category=DetectionCategory.PII_LEAK,
                        rule_id="PII_PAYMENT_CARD_LUHN",
                        risk_score=0.95,
                        description="Detected valid payment card passing Luhn validation",
                        sanitized_evidence=f"****-****-****-{digits_only[-4:]}",
                    )
                )

        # 3. Vietnamese Citizen ID (CCCD)
        for match in self.RE_VN_CCCD.finditer(text):
            candidate = match.group(0)
            if is_valid_vietnamese_cccd(candidate):
                placeholder = f"[REDACTED_VN_CCCD_{len(redaction_map) + 1}]"
                redaction_map[placeholder] = candidate
                redacted_text = redacted_text.replace(candidate, placeholder)
                detections.append(
                    DetectionDetail(
                        category=DetectionCategory.PII_LEAK,
                        rule_id="PII_VN_CCCD_12DIGITS",
                        risk_score=0.90,
                        description="Detected 12-digit Vietnamese Citizen ID (Căn cước công dân)",
                        sanitized_evidence=f"{candidate[:3]}******{candidate[-3:]}",
                    )
                )

        # 4. Vietnamese Phone Numbers
        for match in self.RE_VN_PHONE.finditer(text):
            val = match.group(0)
            placeholder = f"[REDACTED_VN_PHONE_{len(redaction_map) + 1}]"
            redaction_map[placeholder] = val
            redacted_text = redacted_text.replace(val, placeholder)
            detections.append(
                DetectionDetail(
                    category=DetectionCategory.PII_LEAK,
                    rule_id="PII_VN_PHONE_NUMBER",
                    risk_score=0.80,
                    description="Detected valid Vietnamese telephone number",
                    sanitized_evidence=f"{val[:3]}****{val[-3:]}",
                )
            )

        # 5. Email Addresses
        for match in self.RE_EMAIL.finditer(text):
            val = match.group(0)
            placeholder = f"[REDACTED_EMAIL_{len(redaction_map) + 1}]"
            redaction_map[placeholder] = val
            redacted_text = redacted_text.replace(val, placeholder)
            user_part, domain_part = val.split("@", 1)
            detections.append(
                DetectionDetail(
                    category=DetectionCategory.PII_LEAK,
                    rule_id="PII_EMAIL_ADDRESS",
                    risk_score=0.70,
                    description="Detected personal or business email address",
                    sanitized_evidence=f"{user_part[:2]}***@{domain_part}",
                )
            )

        return redacted_text, detections, (redaction_map if preserve_map else {})
