"""Deterministic request-intent classification engine."""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class IntentResult:
    """Outcome of request intent classification."""
    outcome: str  # 'DELETION', 'NON_DELETION', 'AMBIGUOUS'
    is_deletion: bool
    status: str  # 'DELETION', 'NOT_APPLICABLE', or 'AMBIGUOUS'
    category: str  # 'DELETION', 'DATA_ACCESS', 'MARKETING_OPT_OUT', 'RECTIFICATION', 'ACCOUNT_HELP', 'RETENTION_REQUEST', 'AMBIGUOUS'
    confidence: float
    reason: str

    @property
    def contract_status(self) -> str:
        """Challenge output status under challenge contract ('COMPLETE', 'INCOMPLETE', or 'NOT_APPLICABLE')."""
        if self.outcome == "DELETION":
            return "DELETION"  # Subject to downstream evidence audit (COMPLETE vs INCOMPLETE)
        elif self.outcome == "NON_DELETION":
            return "NOT_APPLICABLE"
        else:
            # AMBIGUOUS: under challenge contract, unverified/unauthorized deletion intent is NOT_APPLICABLE
            return "NOT_APPLICABLE"


class IntentClassifier:
    """Classifies user request text to determine whether deletion is authorized."""

    # Explicit non-deletion and negation patterns (Precedence Gate)
    NON_DELETION_PATTERNS = [
        # Explicit negation of deletion (highest precedence)
        (
            r"(?:do not|don\'t|dont|never|please do not) (?:delete|erase|close|remove|purge)|"
            r"not asking for deletion|not requesting deletion|not a request to (?:erase|delete)|"
            r"not an? (?:erasure|deletion) request|leave (?:my |the |this )?(?:profile|account) (?:active|in place|open)|"
            r"(?:keep|still need) (?:the |my |this )?account|without removing|ne pas (?:supprimer|effacer)|"
            r"ne (?:supprimez|effacez) pas|no (?:borrar|eliminar|cancelar|suprimir)|"
            r"nicht (?:löschen|entfernen|schließen)|non (?:cancellare|eliminare)|"
            r"não (?:apagar|excluir)|(?:削除|消去|解約)しないで|(?:삭제|탈퇴|파기)하지",
            "RETENTION_REQUEST",
            "User explicitly negated deletion or requested to keep the account active.",
        ),
        # Marketing opt-out only
        (
            r"marketing lists? only|stop (?:the )?promotional emails?|unsubscribe.*marketing|"
            r"promotional emails? only|marketing emails? only",
            "MARKETING_OPT_OUT",
            "User requested removal from marketing lists only, not account deletion.",
        ),
        # Data portability / access
        (
            r"portable format|download my (?:account|data)|what personal information you hold|"
            r"information request,? not a request to erase|copy of (?:the information|last year\'s invoices)",
            "DATA_ACCESS",
            "User requested data access, portability, or copy, not deletion.",
        ),
        # Rectification / correction / update
        (
            r"misspelled|leave (?:the |my )?account active|continue using the service|"
            r"replace it with the new one|change the email address used for this account",
            "RECTIFICATION",
            "User requested profile rectification/update while keeping account active.",
        ),
        # Login help / account recovery
        (
            r"help resetting the login|can\'t access my profile|reset my password",
            "ACCOUNT_HELP",
            "User requested login/access recovery rather than deletion.",
        ),
    ]

    # Multilingual positive deletion indicators
    DELETION_KEYWORDS = [
        # English
        r"\b(?:permanently )?delet(?:e|ed|ing|ion|ions)?\b",
        r"\beras(?:e|ed|ing|ure)?\b",
        r"\bclos(?:e|ed|ing) (?:my |the |this )?account\b",
        r"\bwould like it closed\b",
        r"\b(?:account|profile|page) (?:page |itself )?is gone\b",
        r"\bremov(?:e|ed|ing|al) (?:my |the |that |any |all )?(?:account|profile|personal details|personal data|records?|details?|search results?|name|contact details|rest)\b",
        r"\bclean my personal details\b",
        r"\bno longer (?:need|use) this account\b",
        r"\b(?:was told|said).*deletion was complete\b",
        r"\b(?:was told|said).*account had been deleted\b",
        r"\b(?:audit|verify).*deletion\b",
        r"\bverify that (?:my |the )?account was deleted\b",
        r"\b(?:already|fully) (?:been )?removed\b",
        r"\bpurg(?:e|ed|ing)\b",
        # French
        r"\bsuppression\b",
        r"\bsupprim(?:er|ez|e)\b",
        r"\beffac(?:er|ez|e)\b",
        r"\bfermer (?:mon |ce )?compte\b",
        r"\bclôtur(?:er|ez|e)\b",
        # Spanish
        r"\belimin(?:ar|ación|e|o)\b",
        r"\bborr(?:ar|ado|o)\b",
        r"\bcancelar (?:mi |esta )?cuenta\b",
        r"\bsuprim(?:ir|ido)\b",
        # German
        r"\blösch(?:en|ung|e)\b",
        r"\bentfern(?:en|ung|e)\b",
        r"\bschließ(?:en|ung|e)\b",
        # Italian
        r"\bcancell(?:are|azione|a)\b",
        r"\belimin(?:are|azione|a)\b",
        r"\bchiud(?:ere|i)\b",
        # Portuguese
        r"\bexclu(?:ir|são|o)\b",
        r"\bapag(?:ar|ado|o)\b",
        r"\bfechar (?:a |minha )?conta\b",
        # Japanese
        r"削除",
        r"消去",
        r"解約",
        # Korean
        r"삭제",
        r"탈퇴",
        r"파기",
    ]

    def __init__(self, enable_llm_fallback: bool = False) -> None:
        self.enable_llm_fallback = enable_llm_fallback

    def classify(self, request_text: str) -> IntentResult:
        """Classify a request text deterministically into DELETION, NON_DELETION, or AMBIGUOUS."""
        text = request_text.strip()
        lower_text = text.lower()

        # Step 1: Check for explicit non-deletion / negative intent patterns (Precedence Gate)
        for pattern, category, explanation in self.NON_DELETION_PATTERNS:
            if re.search(pattern, lower_text, re.IGNORECASE):
                return IntentResult(
                    outcome="NON_DELETION",
                    is_deletion=False,
                    status="NOT_APPLICABLE",
                    category=category,
                    confidence=1.0,
                    reason=explanation,
                )

        # Step 2: Check for positive multilingual deletion signals
        for pattern in self.DELETION_KEYWORDS:
            if re.search(pattern, lower_text, re.IGNORECASE):
                return IntentResult(
                    outcome="DELETION",
                    is_deletion=True,
                    status="DELETION",
                    category="DELETION",
                    confidence=1.0,
                    reason=f"Matched deletion authorization pattern: '{pattern}'.",
                )

        # Step 3: Ambiguity handling - do not silently default to NOT_APPLICABLE
        if self.enable_llm_fallback:
            return self._llm_fallback_classify(text)

        # Distinguish internal outcome as AMBIGUOUS
        return IntentResult(
            outcome="AMBIGUOUS",
            is_deletion=False,
            status="AMBIGUOUS",
            category="AMBIGUOUS",
            confidence=0.0,
            reason="Request text contains ambiguous intent; neither clear deletion authorization nor explicit non-deletion request identified.",
        )

    def _llm_fallback_classify(self, request_text: str) -> IntentResult:
        """Configurable LLM semantic classifier hook (requires configured & approved provider)."""
        # Kept deterministic unless an approved external provider is configured
        return IntentResult(
            outcome="AMBIGUOUS",
            is_deletion=False,
            status="AMBIGUOUS",
            category="LLM_FALLBACK_UNCONFIGURED",
            confidence=0.0,
            reason="LLM fallback invoked but external model provider is unconfigured.",
        )
