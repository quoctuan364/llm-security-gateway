from packages.security_engine.src.detectors.pii import (
    PIIDetector,
    is_valid_vietnamese_cccd,
    luhn_checksum_is_valid,
)


def test_luhn_algorithm_validation():
    # Valid Visa card (standard test card)
    assert luhn_checksum_is_valid("4532015112830366") is True
    # Invalid card number (fails checksum)
    assert luhn_checksum_is_valid("4532015112830367") is False
    # Too short
    assert luhn_checksum_is_valid("1234") is False


def test_vietnamese_cccd_validation():
    # Valid 12 digits with valid province code 079 (TP. Hồ Chí Minh)
    assert is_valid_vietnamese_cccd("079094001234") is True
    # Invalid province code 999
    assert is_valid_vietnamese_cccd("999094001234") is False
    # Not 12 digits
    assert is_valid_vietnamese_cccd("0790940012") is False


def test_pii_detector_vietnamese_phone_redaction():
    detector = PIIDetector()
    text = "Xin chào, hãy liên hệ tôi qua số 0912345678 hoặc +84987654321 nhé!"
    redacted, detections, mapping = detector.scan_and_redact(text)

    assert "0912345678" not in redacted
    assert "+84987654321" not in redacted
    assert "[REDACTED_VN_PHONE_1]" in redacted
    assert "[REDACTED_VN_PHONE_2]" in redacted
    assert len(detections) == 2


def test_pii_detector_payment_card_redaction():
    detector = PIIDetector()
    text = "Thanh toán với thẻ 4532-0151-1283-0366 ngay bây giờ."
    redacted, detections, _ = detector.scan_and_redact(text)

    assert "4532-0151-1283-0366" not in redacted
    assert "[REDACTED_PAYMENT_CARD_" in redacted
    assert any(d.rule_id == "PII_PAYMENT_CARD_LUHN" for d in detections)


def test_pii_detector_api_keys_and_email():
    detector = PIIDetector()
    text = "Contact support@aegis.dev with AWS key AKIAIOSFODNN7EXAMPLE and OpenAI sk-proj-1234567890abcdef1234567890abcdef"
    redacted, detections, _ = detector.scan_and_redact(text)

    assert "support@aegis.dev" not in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "sk-proj-1234567890abcdef1234567890abcdef" not in redacted
    assert any(d.rule_id == "SECRET_AWS_KEY" for d in detections)
    assert any(d.rule_id == "SECRET_OPENAI_KEY" for d in detections)
    assert any(d.rule_id == "PII_EMAIL_ADDRESS" for d in detections)
