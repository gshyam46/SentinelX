"""OWASP LLM Top 10 check registry."""

from backend.modules.ai.llm_security.checks.prompt_injection import PromptInjectionCheck
from backend.modules.ai.llm_security.checks.insecure_output import InsecureOutputCheck
from backend.modules.ai.llm_security.checks.training_poisoning import TrainingPoisoningCheck
from backend.modules.ai.llm_security.checks.model_dos import ModelDenialOfServiceCheck
from backend.modules.ai.llm_security.checks.supply_chain import SupplyChainCheck
from backend.modules.ai.llm_security.checks.sensitive_disclosure import SensitiveDisclosureCheck
from backend.modules.ai.llm_security.checks.plugin_misuse import PluginMisuseCheck
from backend.modules.ai.llm_security.checks.excessive_agency import ExcessiveAgencyCheck
from backend.modules.ai.llm_security.checks.overreliance import OverrelianceCheck
from backend.modules.ai.llm_security.checks.model_theft import ModelTheftCheck

ALL_CHECKS = [
    PromptInjectionCheck,
    InsecureOutputCheck,
    TrainingPoisoningCheck,
    ModelDenialOfServiceCheck,
    SupplyChainCheck,
    SensitiveDisclosureCheck,
    PluginMisuseCheck,
    ExcessiveAgencyCheck,
    OverrelianceCheck,
    ModelTheftCheck,
]

__all__ = [
    "PromptInjectionCheck",
    "InsecureOutputCheck",
    "TrainingPoisoningCheck",
    "ModelDenialOfServiceCheck",
    "SupplyChainCheck",
    "SensitiveDisclosureCheck",
    "PluginMisuseCheck",
    "ExcessiveAgencyCheck",
    "OverrelianceCheck",
    "ModelTheftCheck",
    "ALL_CHECKS",
]
