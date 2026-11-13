"""Local control catalog. These mappings are maintained by this package."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    feature: str
    techniques: tuple[str, ...]
    evidence: str


CONTROLS = (
    Control("tool-authorization", "Authorize every tool action", "tools",
            ("AML.T0053", "AML.T0085.001", "AML.T0086", "AML.T0101"),
            "Caller, tenant, action and resource policy plus allow/deny results."),
    Control("tool-approval", "Approve high-impact side effects", "tools",
            ("AML.T0053", "AML.T0094", "AML.T0101", "AML.T0142"),
            "Effect policy and audit records showing approval before execution."),
    Control("context-trust", "Keep external content outside the instruction boundary", "llm",
            ("AML.T0051", "AML.T0051.000", "AML.T0051.001", "AML.T0051.002",
             "AML.T0054", "AML.T0093", "AML.T0129", "AML.T0131"),
            "Context trust policy and reviewed synthetic input-handling results."),
    Control("retrieval-authorization", "Apply document ACLs before model context", "retrieval",
            ("AML.T0064", "AML.T0082", "AML.T0085.000"),
            "Document-level policy plus authorization results across synthetic tenants."),
    Control("retrieval-provenance", "Validate retrieval ingestion provenance", "retrieval",
            ("AML.T0066", "AML.T0070", "AML.T0071"),
            "Ingestion source allowlist and rejection records for unapproved documents."),
    Control("renderer-egress", "Constrain rendering, previews and outbound destinations", "rendering",
            ("AML.T0025", "AML.T0067", "AML.T0067.000", "AML.T0077", "AML.T0136"),
            "Output encoding policy, effective egress policy and observed deny decisions."),
    Control("session-isolation", "Isolate session context and enforce expiry", "memory",
            ("AML.T0080", "AML.T0080.000", "AML.T0080.001", "AML.T0085.002", "AML.T0092"),
            "Session lifecycle results, storage policy and cross-session access decisions."),
    Control("artifact-integrity", "Verify model and tool artifacts before promotion", "artifacts",
            ("AML.T0010", "AML.T0010.001", "AML.T0010.005", "AML.T0060", "AML.T0076",
             "AML.T0109", "AML.T0110", "AML.T0110.001", "AML.T0115", "AML.T0115.001", "AML.T0115.002"),
            "Approved publishers, immutable digests, provenance and promotion approvals."),
    Control("secret-isolation", "Keep credentials outside model and worker context", "credentials",
            ("AML.T0055", "AML.T0083", "AML.T0085.003", "AML.T0091.000", "AML.T0098"),
            "Workload identity and secret-scoping policy plus audit records."),
    Control("runtime-isolation", "Constrain execution workers and evaluation environments", "execution",
            ("AML.T0050", "AML.T0097", "AML.T0105", "AML.T0112.000", "AML.T0133"),
            "Runtime permission snapshot, workload identity bindings and isolation results."),
    Control("service-exposure", "Require authenticated private management surfaces", "ai_service",
            ("AML.T0049", "AML.T0096", "AML.T0132", "AML.T0139"),
            "Service inventory, authentication configuration and access policy."),
    Control("inference-abuse", "Enforce identity-based inference budgets and monitoring", "ai_service",
            ("AML.T0046", "AML.T0135", "AML.T0137", "AML.T0137.000", "AML.T0137.001",
             "AML.T0137.002", "AML.T0137.003"),
            "Usage quotas, identity-scoped aggregation and reviewed abuse alerts."),
    Control("training-lineage", "Verify and quarantine untrusted training inputs", "training",
            ("AML.T0059", "AML.T0115.000", "AML.T0145"),
            "Dataset lineage, snapshot hashes and approval records."),
    Control("predictive-fallback", "Use independent verification for critical predictions", "predictive",
            ("AML.T0015", "AML.T0048.003"),
            "Independent decision signal, fallback policy and evaluation by input group."),
)
