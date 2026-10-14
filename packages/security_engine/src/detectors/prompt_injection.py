import re
from typing import List, Tuple

from packages.shared.src.models.decision import (
    DetectionCategory,
    DetectionDetail,
)


class PromptInjectionDetector:
    """
    Multi-layer heuristic and rule-based classifier for prompt injection,
    jailbreak attempts, delimiter manipulation, and system prompt exfiltration.
    """

    INJECTION_RULES = [
        (
            "INJECTION_INSTRUCTION_OVERRIDE",
            re.compile(
                r'(?i)\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|your\s+|the\s+|any\s+)*(?:previous\s+|prior\s+|above\s+|existing\s+|system\s+)*(?:instructions|prompts|rules|guidelines|directions)\b'
            ),
            0.92,
            "Direct attempt to override or ignore previous system instructions",
        ),
        (
            "INJECTION_JAILBREAK_PERSONA",
            re.compile(
                r'(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:in\s+|a\s+|an\s+)?(?:DAN|developer\s+mode|unfiltered|jailbroken|evil|do\s+anything\s+now|unrestricted|AIM)\b'
            ),
            0.88,
            "Classic jailbreak persona adoption (e.g., DAN, Developer Mode, AIM)",
        ),
        (
            "INJECTION_DELIMITER_HIJACKING",
            re.compile(
                r'(?i)(?:<system>|\[system(?:\s+prompt)?\]|###\s*system:|---\s*begin\s+system\s+prompt\s*---|\bAssistant:\s*Sure,\s*I\s*can\s*bypass)'
            ),
            0.85,
            "Attempt to inject fake system delimiters or spoof assistant conversation turns",
        ),
        (
            "INJECTION_PROMPT_EXFILTRATION",
            re.compile(
                r'(?i)\b(?:print|repeat|output|show|echo|reveal|give\s+me)\s+(?:your\s+|the\s+|all\s+)*(?:initial\s+|first\s+|system\s+|hidden\s+)*(?:prompt|instructions|system\s+message)\b'
            ),
            0.82,
            "Attempt to extract or exfiltrate private system instructions",
        ),
        (
            "INJECTION_HYPOTHETICAL_EVASION",
            re.compile(
                r'(?i)\b(?:for\s+a\s+fictional\s+story|in\s+a\s+hypothetical\s+world\s+without\s+rules|educational\s+purposes\s+only\s+how\s+to\s+(?:hack|exploit|bypass))\b'
            ),
            0.65,
            "Hypothetical or fictional framing to evade safety guardrails",
        ),
        (
            "INJECTION_BASE64_EXEC_COMMAND",
            re.compile(
                r'(?i)\b(?:decode\s+(?:the\s+following\s+)?base64\s+(?:and\s+execute|and\s+follow|string)|base64:\s*[A-Za-z0-9+/=]{20,})\b'
            ),
            0.75,
            "Instruction to decode and execute obfuscated base64 payload",
        ),
    ]

    def evaluate(self, text: str) -> Tuple[float, List[DetectionDetail]]:
        """
        Evaluates input text against known prompt injection and jailbreak signatures.
        Returns a composite risk score (0.0 - 1.0) and list of detection details.
        """
        detections: List[DetectionDetail] = []
        max_score = 0.0

        for rule_id, pattern, weight, description in self.INJECTION_RULES:
            match = pattern.search(text)
            if match:
                evidence = match.group(0)
                sanitized = evidence[:60] + "..." if len(evidence) > 60 else evidence
                detections.append(
                    DetectionDetail(
                        category=DetectionCategory.PROMPT_INJECTION,
                        rule_id=rule_id,
                        risk_score=weight,
                        description=description,
                        sanitized_evidence=sanitized,
                    )
                )
                if weight > max_score:
                    max_score = weight

        # Compound penalty if multiple injection rules are triggered simultaneously
        if len(detections) > 1:
            compound_score = min(1.0, max_score + 0.05 * (len(detections) - 1))
        else:
            compound_score = max_score

        return compound_score, detections
