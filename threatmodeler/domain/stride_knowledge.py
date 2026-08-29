"""OWASP-aligned STRIDE threat categorization knowledge.

This module provides mappings from STRIDE categories to their corresponding
security properties, controls, and mitigation techniques per OWASP guidelines.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from threatmodeler.contracts.artifacts.enums import StrideCategory


class SecurityProperty(StrEnum):
    """Security properties violated by STRIDE categories."""

    AUTHENTICATION = "authentication"
    INTEGRITY = "integrity"
    NON_REPUDIATION = "non_repudiation"
    CONFIDENTIALITY = "confidentiality"
    AVAILABILITY = "availability"
    AUTHORIZATION = "authorization"


class StrideSecurityMapping(BaseModel):
    """Mapping from a STRIDE category to its security context."""

    model_config = ConfigDict(frozen=True)

    category: StrideCategory
    violated_property: SecurityProperty
    description: str
    control_focus: str
    mitigation_techniques: tuple[str, ...]


class StrideKnowledgeBase:
    """OWASP-aligned STRIDE threat categorization knowledge base.

    Provides deterministic mappings from STRIDE categories to security
    properties and mitigation techniques per OWASP Threat Modeling Process.
    """

    def __init__(self) -> None:
        self._mappings = self._build_mappings()

    def _build_mappings(self) -> dict[StrideCategory, StrideSecurityMapping]:
        return {
            StrideCategory.SPOOFING: StrideSecurityMapping(
                category=StrideCategory.SPOOFING,
                violated_property=SecurityProperty.AUTHENTICATION,
                description="Attacker pretends to be someone or something else",
                control_focus="Authentication controls",
                mitigation_techniques=(
                    "Appropriate authentication mechanisms",
                    "Protect secret data (credentials, tokens)",
                    "Do not store secrets in plaintext",
                    "Multi-factor authentication for sensitive operations",
                ),
            ),
            StrideCategory.TAMPERING: StrideSecurityMapping(
                category=StrideCategory.TAMPERING,
                violated_property=SecurityProperty.INTEGRITY,
                description="Attacker modifies data or code without authorization",
                control_focus="Integrity controls",
                mitigation_techniques=(
                    "Authorization checks before modification",
                    "Cryptographic hashes for data integrity",
                    "Message authentication codes (MACs)",
                    "Digital signatures for non-repudiation",
                    "Input validation and sanitization",
                ),
            ),
            StrideCategory.REPUDIATION: StrideSecurityMapping(
                category=StrideCategory.REPUDIATION,
                violated_property=SecurityProperty.NON_REPUDIATION,
                description="Attacker denies performing an action",
                control_focus="Audit and non-repudiation controls",
                mitigation_techniques=(
                    "Digital signatures on transactions",
                    "Secure timestamps with trusted sources",
                    "Comprehensive audit trails",
                    "Tamper-evident logging",
                    "Secure log storage and transmission",
                ),
            ),
            StrideCategory.INFORMATION_DISCLOSURE: StrideSecurityMapping(
                category=StrideCategory.INFORMATION_DISCLOSURE,
                violated_property=SecurityProperty.CONFIDENTIALITY,
                description="Attacker gains access to restricted information",
                control_focus="Confidentiality controls",
                mitigation_techniques=(
                    "Authorization checks before data access",
                    "Encryption in transit (TLS)",
                    "Encryption at rest",
                    "Privacy-enhancing protocols",
                    "Data masking and tokenization",
                    "Least privilege access",
                ),
            ),
            StrideCategory.DENIAL_OF_SERVICE: StrideSecurityMapping(
                category=StrideCategory.DENIAL_OF_SERVICE,
                violated_property=SecurityProperty.AVAILABILITY,
                description="Attacker prevents legitimate access to resources",
                control_focus="Availability controls",
                mitigation_techniques=(
                    "Authentication to prevent anonymous abuse",
                    "Authorization and quotas",
                    "Request filtering and validation",
                    "Throttling and rate limiting",
                    "Resource pooling and graceful degradation",
                    "Redundancy and failover",
                ),
            ),
            StrideCategory.ELEVATION_OF_PRIVILEGE: StrideSecurityMapping(
                category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                violated_property=SecurityProperty.AUTHORIZATION,
                description="Attacker gains higher privileges than granted",
                control_focus="Authorization controls",
                mitigation_techniques=(
                    "Run with least privilege",
                    "Role-based access control (RBAC)",
                    "Input validation to prevent injection",
                    "Sandboxing and isolation",
                    "Privilege separation",
                    "Regular privilege audits",
                ),
            ),
        }

    def get_mapping(self, category: StrideCategory) -> StrideSecurityMapping:
        """Return the security mapping for a STRIDE category.

        Args:
            category: STRIDE threat category to look up.

        Returns:
            Mapping containing violated property and mitigation techniques.
        """
        return self._mappings[category]

    def get_all_mappings(self) -> tuple[StrideSecurityMapping, ...]:
        """Return all STRIDE security mappings in category order.

        Returns:
            Tuple of mappings ordered by STRIDE category enum values.
        """
        return tuple(
            self._mappings[category]
            for category in StrideCategory
        )

    def format_threat_guidance(self) -> str:
        """Format STRIDE-to-security-property guidance for prompts.

        Returns:
            Formatted text suitable for inclusion in LLM prompts.
        """
        lines = [
            "STRIDE-to-Security-Property Mapping (per OWASP):",
        ]
        for mapping in self.get_all_mappings():
            lines.append(
                f"- {mapping.category.value.upper()}: Targets {mapping.violated_property.value}. "
                f"{mapping.description}. Focus on {mapping.control_focus}."
            )
        return "\n".join(lines)

    def format_mitigation_guidance(self) -> str:
        """Format STRIDE-to-mitigation-technique guidance for prompts.

        Returns:
            Formatted text suitable for inclusion in LLM prompts.
        """
        lines = [
            "STRIDE Mitigation Techniques (per OWASP):",
        ]
        for mapping in self.get_all_mappings():
            techniques = "; ".join(mapping.mitigation_techniques)
            lines.append(
                f"- {mapping.category.value.upper()}: {techniques}"
            )
        return "\n".join(lines)

    def format_risk_assessment_guidance(self) -> str:
        """Format OWASP qualitative risk-assessment questions for prompts.

        Returns:
            Formatted text suitable for inclusion in LLM prompts.
        """
        return "\n".join(
            [
                "OWASP Qualitative Risk Assessment (populate on every threat when "
                "source evidence allows; leave null only when genuinely unknown):",
                "Exploitability (`exploitability`):",
                "- exploitable_remotely: Can an attacker exploit this remotely "
                "without local access?",
                "- requires_authentication: Does the attacker need to be "
                "authenticated to exploit this threat?",
                "- exploit_automatable: Can the exploitation be automated "
                "(scripted attack)?",
                "Impact (`impact_assessment`):",
                "- full_system_compromise: Can an attacker completely take over "
                "or destroy the system?",
                "- admin_access_possible: Can an attacker gain administration "
                "access to the system?",
                "- system_crash_possible: Can an attacker crash the system or "
                "make it unavailable?",
                "- sensitive_data_exposure: Can the attacker obtain access to "
                "highly sensitive information?",
            ]
        )

    def format_risk_scoring_guidance(self) -> str:
        """Format OWASP-aligned severity/likelihood scoring rules for prompts.

        Mirrors RiskScoringService so agent-backed risk registers stay aligned
        with deterministic scoring when assessments are present.

        Returns:
            Formatted text suitable for inclusion in LLM prompts.
        """
        return "\n".join(
            [
                "OWASP Risk Scoring (derive severity/likelihood from linked "
                "threat assessments when present):",
                "Severity from impact_assessment:",
                "- full_system_compromise true -> critical",
                "- admin_access_possible or sensitive_data_exposure true -> high",
                "- system_crash_possible true -> high",
                "- otherwise fall back to STRIDE category defaults "
                "(information_disclosure/elevation_of_privilege -> high; "
                "spoofing/tampering/denial_of_service -> medium; "
                "repudiation -> low)",
                "Likelihood from exploitability:",
                "- remotely + automatable + no auth -> almost_certain",
                "- remotely + automatable -> likely",
                "- remotely -> likely",
                "- not remote but automatable -> possible",
                "- not remote and not automatable -> unlikely",
                "- when exploitability is absent, use external entry-point "
                "exposure (external component -> likely; otherwise possible)",
            ]
        )

    def format_response_type_guidance(self) -> str:
        """Format OWASP risk-response category rubric for prompts.

        Returns:
            Formatted text suitable for inclusion in LLM prompts.
        """
        return "\n".join(
            [
                "OWASP Risk Response Types (`response_type`):",
                "- mitigate (default): Add controls to reduce impact or "
                "likelihood when the threat remains in scope.",
                "- eliminate: Use only when a design change removes the "
                "vulnerable component or attack path entirely.",
                "- transfer: Use when risk is explicitly shifted to an insurer, "
                "customer, or third-party assumption evidenced in the input.",
                "- accept: Use only with explicit rationale; identify who "
                "accepted the risk (populate owner when accepting).",
                "Do not claim a response is implemented without evidence.",
            ]
        )

    def format_threat_status_guidance(self) -> str:
        """Format OWASP threat profile status guidance for prompts.

        Returns:
            Formatted text suitable for inclusion in LLM prompts.
        """
        return "\n".join(
            [
                "OWASP Threat Profiles (`status` on each threat):",
                "- identified / analyzed: threat documented but not yet treated.",
                "- partially_mitigated: some countermeasures are evidenced but "
                "gaps remain.",
                "- mitigated: countermeasures fully address the threat per evidence.",
                "- accepted: risk explicitly accepted with rationale.",
            ]
        )

    def format_control_type_guidance(self) -> str:
        """Format layered defense control-type guidance for mitigations.

        Returns:
            Formatted text suitable for inclusion in LLM prompts.
        """
        return "\n".join(
            [
                "Security Control Types (`control_type` on each mitigation):",
                "- preventive: blocks or reduces likelihood before impact.",
                "- detective: identifies abuse or failure after it begins.",
                "- corrective: remediates or contains impact after detection.",
                "- compensating: alternative control when primary control is weak "
                "or absent.",
            ]
        )

    def format_asset_trust_guidance(self) -> str:
        """Format OWASP asset-to-trust-level cross-reference guidance.

        Returns:
            Formatted text suitable for inclusion in LLM prompts.
        """
        return (
            "Cross-reference each asset with applicable trust levels from "
            "`trust_levels` by populating `trust_level_ids` to indicate which "
            "access rights can interact with the asset."
        )
