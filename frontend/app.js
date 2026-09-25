const API_CONFIG = {
    baseUrl: "http://127.0.0.1:8000/api",
    timeout: 10000,
    endpoints: {
        case: "/case",
        artifacts: "/artifacts",
        fragments: "/fragments",
        timeline: "/timeline",
        audit: "/audit"
    }
};

// Member 1 should allow the Live Server origin in FastAPI CORS settings.

const state = {
    mode: "demo",
    case: null,
    stats: null,
    artifacts: [],
    fragments: [],
    timeline: [],
    audit: null,
    selectedFragment: null,
    selectedArtifact: null
};

let apiRequestFailed = false;

const MOCK_DATA = {
    caseInfo: {
        id: "CASE-2026-001",
        evidenceId: "EVC-18-421",
        sha256: "a9d3c1ae6f3d0b4a93d4ba3586f61e9a5d0e9b827a5d3273b09f0af1c9d7ee93",
        inputTimestamp: "2026-09-21 09:42 UTC",
        processingTimestamp: "2026-09-22 14:11 UTC",
        operationCount: 14,
        originalHash: "66fb4a6df0cb9ce9855020d4f5c9d456a8d6bf5a8a3db1763f6780aefaf7d8b9",
        recoveredArtifactHash: "4a1c9ab1c0ef85ea4be0b8e1f49cb1dbd2db94cb1c2710a7d198e8022c8d3431",
        provenanceStatus: "Chain preserved"
    },
    stats: {
        fileCount: 1402,
        recovered: 84,
        confidence: 91,
        totalFragments: 8593,
        inferred: 11,
        missing: 5
    },
    artifacts: [
        {
            name: "report.pdf",
            type: "PDF",
            recovery: 82,
            integrity: 82,
            corruption: 18,
            state: "partial",
            explanation: "The Anvaya system identified a probable continuation of the document structure from surviving header blocks and page metadata. The recovered body is supported by file-signature alignment and object-stream continuity, but not all content is fully validated.",
            explainability: [
                "Structural compatibility: Object stream markers match expected PDF boundaries.",
                "Byte-pattern continuity: Surviving bytes align with surrounding segments.",
                "File-signature compatibility: Header and trailer signatures remain consistent.",
                "Metadata consistency: Document revision fields are coherent with recovered fragments.",
                "Human review recommendation: Validate page-order reconstruction before legal use."
            ]
        },
        {
            name: "suspect_photo.jpg",
            type: "JPEG",
            recovery: 94,
            integrity: 94,
            corruption: 6,
            state: "recovered",
            explanation: "The image container remains structurally coherent with verified EXIF markers and a stable file signature. The recovered region is supported by contiguous data blocks and hash continuity, with only minor corruption at trailing segments.",
            explainability: [
                "Structural compatibility: EXIF segments and frame markers remain intact.",
                "Byte-pattern continuity: No major discontinuities were detected across the payload.",
                "File-signature compatibility: JPEG markers match expected encoding structure.",
                "Metadata consistency: Camera metadata remains internally consistent.",
                "Hash verification: Image hash chain is intact for the validated region."
            ]
        },
        {
            name: "sys_auth.log",
            type: "TXT",
            recovery: 61,
            integrity: 61,
            corruption: 39,
            state: "partial",
            explanation: "The log stream shows partial continuity but includes multiple corrupted sectors. Anvaya infers probable event ordering from adjacent records and timestamp patterns, while preserving the distinction that missing records remain unverified.",
            explainability: [
                "Structural compatibility: Event delimiters are partially preserved.",
                "Byte-pattern continuity: Some sequence gaps align with known timestamp formats.",
                "File-signature compatibility: Plain-text records remain consistent in delimiters and key-value structure.",
                "Metadata consistency: Time ordering is coherent across recovered entries.",
                "Anomaly indicators: Several records are incomplete or overwritten and require human review."
            ]
        }
    ],
    fragments: [
        { id: "F001", artifact: "report.pdf", type: "Header Block", state: "recovered", compatibility: 0.98, hashStatus: "Verified", reasoning: "Fragment F001 provides the document signature and page-structure baseline used to anchor reconstruction. The relationship to adjacent fragments is supported by stable header markers and file-boundary continuity.", connections: ["F004"], x: 90, y: 150 },
        { id: "F004", artifact: "report.pdf", type: "Document Map", state: "recovered", compatibility: 0.94, hashStatus: "Verified", reasoning: "Fragment F004 follows F001 with compatible structural markers and expected object-stream boundaries. The connection is supported by byte-pattern continuity and page-index alignment.", connections: ["F007"], x: 200, y: 130 },
        { id: "F007", artifact: "report.pdf", type: "Object Stream", state: "recovered", compatibility: 0.94, hashStatus: "Verified", reasoning: "Fragment F007 follows F004 with compatible structural markers and expected object-stream boundaries. The connection is supported by byte-pattern continuity and file-structure compatibility.", connections: ["F009", "F004"], x: 330, y: 170 },
        { id: "F009", artifact: "report.pdf", type: "Embedded Object", state: "inferred", compatibility: 0.81, hashStatus: "Pending", reasoning: "Fragment F009 shows a strong probable match to recovered content, but the region is partially reconstructed and still requires analyst review because its exact byte sequence cannot be fully confirmed.", connections: ["F013", "F007"], x: 500, y: 140 },
        { id: "F011", artifact: "sys_auth.log", type: "Log Block", state: "missing", compatibility: 0.26, hashStatus: "Corrupted", reasoning: "Fragment F011 is missing or heavily overwritten. The system indicates a low-confidence relationship only because surrounding metadata is partially preserved and does not establish reliable continuity.", connections: [], x: 430, y: 250 },
        { id: "F013", artifact: "report.pdf", type: "Trailer Segment", state: "recovered", compatibility: 0.9, hashStatus: "Verified", reasoning: "Fragment F013 closes the sequence with coherent trailer metadata and stable structural markers. The relationship is consistent with the reconstructed document chain but is not assumed to be the only valid path.", connections: ["F009"], x: 620, y: 160 }
    ],
    timeline: [
        { time: "09:42", operation: "Evidence ingestion", status: "success", explanation: "Source media was catalogued and reserved for forensic processing." },
        { time: "09:49", operation: "SHA-256 calculated", status: "success", explanation: "Original evidence hash generated and stored as a reference baseline." },
        { time: "10:03", operation: "Fragment detection", status: "success", explanation: "Recovered fragments were enumerated and classified by file-signature pattern." },
        { time: "10:18", operation: "Duplicate detection", status: "warning", explanation: "Redundant copies were flagged and reviewed for hash divergence." },
        { time: "10:44", operation: "Fragment matching", status: "success", explanation: "Compatible structural chains were identified between adjacent surviving blocks." },
        { time: "11:12", operation: "Reconstruction attempt", status: "warning", explanation: "Partial reconstruction was attempted only where evidence continuity remained valid." },
        { time: "12:06", operation: "AI analysis", status: "success", explanation: "Anvaya inferred probable relationships while preserving the distinction between evidence and hypothesis." },
        { time: "12:30", operation: "Integrity verification", status: "muted", explanation: "Recovered structure and provenance chain reviewed for final audit readiness." }
    ]
};

function mockCaseResponse() {
    return {
        case_id: MOCK_DATA.caseInfo.id,
        stats: {
            file_count: MOCK_DATA.stats.fileCount,
            recovery_percentage: MOCK_DATA.stats.recovered,
            ai_confidence: MOCK_DATA.stats.confidence,
            fragment_count: MOCK_DATA.stats.totalFragments
        },
        ...MOCK_DATA.caseInfo
    };
}

function mockAuditResponse() {
    return {
        case_id: MOCK_DATA.caseInfo.id,
        evidence_id: MOCK_DATA.caseInfo.evidenceId,
        sha256: MOCK_DATA.caseInfo.sha256,
        input_timestamp: MOCK_DATA.caseInfo.inputTimestamp,
        processing_timestamp: MOCK_DATA.caseInfo.processingTimestamp,
        operation_count: MOCK_DATA.caseInfo.operationCount,
        original_evidence_hash: MOCK_DATA.caseInfo.originalHash,
        recovered_artifact_hash: MOCK_DATA.caseInfo.recoveredArtifactHash,
        provenance_status: MOCK_DATA.caseInfo.provenanceStatus
    };
}

function endpointUrl(endpoint) {
    return `${API_CONFIG.baseUrl}${endpoint}`;
}

async function fetchJson(endpoint) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.timeout);

    try {
        const response = await fetch(endpointUrl(endpoint), {
            method: "GET",
            headers: { Accept: "application/json" },
            signal: controller.signal
        });

        if (!response.ok) {
            throw new Error(`Request failed with HTTP ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        apiRequestFailed = true;
        console.warn(`Backend request unavailable: ${endpoint}`, error);
        return null;
    } finally {
        clearTimeout(timeoutId);
    }
}

async function fetchCaseData() {
    return (await fetchJson(API_CONFIG.endpoints.case)) || mockCaseResponse();
}

async function fetchArtifacts() {
    return (await fetchJson(API_CONFIG.endpoints.artifacts)) || MOCK_DATA.artifacts;
}

async function fetchFragments() {
    return (await fetchJson(API_CONFIG.endpoints.fragments)) || MOCK_DATA.fragments;
}

async function fetchFragmentDetails(fragmentId) {
    const fragments = await fetchFragments();
    return fragments.find((fragment) => fragment.id === fragmentId) || null;
}

async function fetchTimeline() {
    return (await fetchJson(API_CONFIG.endpoints.timeline)) || MOCK_DATA.timeline;
}

async function fetchAuditData() {
    return (await fetchJson(API_CONFIG.endpoints.audit)) || mockAuditResponse();
}

function normalizeCase(caseResponse) {
    const stats = caseResponse?.stats || {};
    return {
        ...caseResponse,
        id: caseResponse?.case_id || caseResponse?.id || MOCK_DATA.caseInfo.id,
        evidenceId: caseResponse?.evidence_id || caseResponse?.evidenceId || MOCK_DATA.caseInfo.evidenceId,
        sha256: caseResponse?.sha256 || MOCK_DATA.caseInfo.sha256,
        inputTimestamp: caseResponse?.input_timestamp || caseResponse?.inputTimestamp || MOCK_DATA.caseInfo.inputTimestamp,
        processingTimestamp: caseResponse?.processing_timestamp || caseResponse?.processingTimestamp || MOCK_DATA.caseInfo.processingTimestamp,
        operationCount: caseResponse?.operation_count || caseResponse?.operationCount || MOCK_DATA.caseInfo.operationCount,
        originalHash: caseResponse?.original_evidence_hash || caseResponse?.originalHash || MOCK_DATA.caseInfo.originalHash,
        recoveredArtifactHash: caseResponse?.recovered_artifact_hash || caseResponse?.recoveredArtifactHash || MOCK_DATA.caseInfo.recoveredArtifactHash,
        provenanceStatus: caseResponse?.provenance_status || caseResponse?.provenanceStatus || MOCK_DATA.caseInfo.provenanceStatus,
        stats: {
            fileCount: stats.file_count ?? stats.fileCount ?? MOCK_DATA.stats.fileCount,
            recovered: stats.recovery_percentage ?? stats.recovered ?? MOCK_DATA.stats.recovered,
            confidence: stats.ai_confidence ?? stats.confidence ?? MOCK_DATA.stats.confidence,
            totalFragments: stats.fragment_count ?? stats.totalFragments ?? MOCK_DATA.stats.totalFragments,
            inferred: stats.inferred ?? MOCK_DATA.stats.inferred,
            missing: stats.missing ?? MOCK_DATA.stats.missing
        }
    };
}

function normalizeArtifact(artifact) {
    return {
        ...artifact,
        recovery: artifact.recovery ?? artifact.integrity ?? 0,
        integrity: artifact.integrity ?? artifact.recovery ?? 0,
        corruption: artifact.corruption ?? 0,
        state: artifact.state || "missing",
        explainability: artifact.explainability || [],
        explanation: artifact.explanation || "No explanatory analysis was supplied by the backend."
    };
}

function normalizeFragment(fragment, index) {
    return {
        ...fragment,
        hashStatus: fragment.hash_status || fragment.hashStatus || "Unknown",
        reasoning: fragment.reasoning || "No matching rationale was supplied by the backend.",
        compatibility: Number(fragment.compatibility ?? 0),
        connections: fragment.connections || [],
        x: fragment.x ?? 90 + (index % 5) * 125,
        y: fragment.y ?? 120 + (index % 3) * 60
    };
}

function normalizeTimeline(event) {
    return {
        ...event,
        time: event.timestamp || event.time || "--:--",
        explanation: event.description || event.explanation || "No event description was supplied."
    };
}

function normalizeAudit(audit) {
    return {
        ...audit,
        caseId: audit?.case_id || audit?.caseId || "",
        evidenceId: audit?.evidence_id || audit?.evidenceId || "",
        sha256: audit?.sha256 || "",
        inputTimestamp: audit?.input_timestamp || audit?.inputTimestamp || "",
        processingTimestamp: audit?.processing_timestamp || audit?.processingTimestamp || "",
        operationCount: audit?.operation_count ?? audit?.operationCount ?? 0,
        originalHash: audit?.original_evidence_hash || audit?.originalHash || "",
        recoveredHash: audit?.recovered_artifact_hash || audit?.recoveredHash || "",
        provenanceStatus: audit?.provenance_status || audit?.provenanceStatus || "Unknown"
    };
}

function renderModeIndicator() {
    const indicator = document.getElementById("modeIndicator");
    const label = document.getElementById("modeLabel");
    const note = document.getElementById("connectionNote");
    const dataSourceNote = document.getElementById("dataSourceNote");
    if (!indicator || !label) return;

    indicator.dataset.mode = state.mode;
    if (state.mode === "live") {
        label.textContent = "LIVE BACKEND";
        if (note) note.textContent = "Connected to the FastAPI forensic engine.";
        if (dataSourceNote) dataSourceNote.textContent = "Live API data";
    } else if (state.mode === "demo") {
        label.textContent = "DEMO MODE";
        if (note) note.textContent = "Backend unavailable - using demonstration dataset.";
        if (dataSourceNote) dataSourceNote.textContent = "Mock / demo data";
    } else {
        label.textContent = "CONNECTING TO FORENSIC ENGINE...";
        if (note) note.textContent = "Loading evidence...";
        if (dataSourceNote) dataSourceNote.textContent = "Loading data";
    }
}

function renderCaseMeta(caseInfo, audit) {
    const label = document.getElementById("caseIdLabel");
    if (label) label.textContent = caseInfo.id || "CASE-2026-001";

    const auditCase = document.getElementById("auditCaseId");
    const evidenceId = document.getElementById("auditEvidenceId");
    const auditHash = document.getElementById("auditHash");
    const inputTime = document.getElementById("auditInputTime");
    const processTime = document.getElementById("auditProcessTime");
    const opCount = document.getElementById("auditOps");
    const originalHash = document.getElementById("auditOriginalHash");
    const recoveredHash = document.getElementById("auditRecoveredHash");
    const provenance = document.getElementById("auditProvenance");

    const auditData = audit || {};
    if (auditCase) auditCase.textContent = auditData.caseId || caseInfo.id || "CASE-2026-001";
    if (evidenceId) evidenceId.textContent = auditData.evidenceId || caseInfo.evidenceId || "EVC-18-421";
    if (auditHash) auditHash.textContent = (auditData.sha256 || caseInfo.sha256 || "a9d3…f4b8").slice(0, 10) + "…" + (auditData.sha256 || caseInfo.sha256 || "a9d3…f4b8").slice(-6);
    if (inputTime) inputTime.textContent = auditData.inputTimestamp || caseInfo.inputTimestamp || "2026-09-21 09:42 UTC";
    if (processTime) processTime.textContent = auditData.processingTimestamp || caseInfo.processingTimestamp || "2026-09-22 14:11 UTC";
    if (opCount) opCount.textContent = auditData.operationCount || caseInfo.operationCount || 14;
    if (originalHash) originalHash.textContent = (auditData.originalHash || caseInfo.originalHash || "66fb…9bb1").slice(0, 10) + "…" + (auditData.originalHash || caseInfo.originalHash || "66fb…9bb1").slice(-6);
    if (recoveredHash) recoveredHash.textContent = (auditData.recoveredHash || caseInfo.recoveredArtifactHash || "4a1c…c80e").slice(0, 10) + "…" + (auditData.recoveredHash || caseInfo.recoveredArtifactHash || "4a1c…c80e").slice(-6);
    if (provenance) provenance.textContent = auditData.provenanceStatus || caseInfo.provenanceStatus || "Chain preserved";
}

function renderCase() {
    renderCaseMeta(state.case, state.audit);
}

function renderAudit() {
    renderCaseMeta(state.case, state.audit);
}

function renderStats(stats) {
    const map = {
        fileCount: document.getElementById("fileCount"),
        recoveredCount: document.getElementById("recoveredCount"),
        confidence: document.getElementById("confidence"),
        fragmentCount: document.getElementById("fragmentCount"),
        recoveredMetric: document.getElementById("recoveredMetric"),
        inferredMetric: document.getElementById("inferredMetric"),
        missingMetric: document.getElementById("missingMetric"),
        recoveredMetricBar: document.getElementById("recoveredMetricBar"),
        inferredMetricBar: document.getElementById("inferredMetricBar"),
        missingMetricBar: document.getElementById("missingMetricBar")
    };

    if (map.fileCount) map.fileCount.textContent = stats.fileCount.toLocaleString();
    if (map.recoveredCount) map.recoveredCount.textContent = `${stats.recovered}%`;
    if (map.confidence) map.confidence.textContent = `${stats.confidence}%`;
    if (map.fragmentCount) map.fragmentCount.textContent = stats.totalFragments.toLocaleString();

    if (map.recoveredMetric) map.recoveredMetric.textContent = `${stats.recovered}%`;
    if (map.inferredMetric) map.inferredMetric.textContent = `${stats.inferred}%`;
    if (map.missingMetric) map.missingMetric.textContent = `${stats.missing}%`;

    if (map.recoveredMetricBar) map.recoveredMetricBar.style.width = `${stats.recovered}%`;
    if (map.inferredMetricBar) map.inferredMetricBar.style.width = `${stats.inferred}%`;
    if (map.missingMetricBar) map.missingMetricBar.style.width = `${stats.missing}%`;
}

function renderArtifactTable(artifacts) {
    const tableBody = document.getElementById("artifactTableBody");
    if (!tableBody) return;

    tableBody.innerHTML = artifacts
        .map((artifact) => {
            const stateClass = artifact.state === "recovered" ? "recovered" : artifact.state === "partial" ? "partial" : "missing";
            const recoveryValue = artifact.recovery ?? artifact.integrity ?? 0;

            return `
                <div class="artifact-row" data-artifact-name="${artifact.name}">
                    <span class="artifact-name">${artifact.name}</span>
                    <span class="artifact-type">${artifact.type}</span>
                    <span class="artifact-recovery">${recoveryValue}%</span>
                    <span class="badge ${stateClass}">${artifact.state}</span>
                </div>
            `;
        })
        .join("");

    tableBody.querySelectorAll(".artifact-row").forEach((row) => {
        row.addEventListener("click", () => {
            const name = row.dataset.artifactName;
            const artifact = artifacts.find((item) => item.name === name);
            if (artifact) {
                state.selectedArtifact = artifact;
                openArtifactModal(artifact);
            }
        });
    });
}

function renderTimeline(events) {
    const timelineList = document.getElementById("timelineList");
    if (!timelineList) return;

    timelineList.innerHTML = events
        .map((event) => {
            const statusClass = {
                success: "success",
                warning: "warning",
                muted: "muted"
            }[event.status] || "muted";

            return `
                <div class="timeline-event">
                    <div class="timeline-time">${event.time}</div>
                    <div class="timeline-copy">
                        <strong>${event.operation}</strong>
                        <span>${event.explanation}</span>
                    </div>
                    <div class="timeline-status ${statusClass}">${event.status}</div>
                </div>
            `;
        })
        .join("");
}

function renderFragmentGraph(fragments) {
    const svg = document.getElementById("fragmentGraph");
    if (!svg) return;

    const stateColors = {
        recovered: "#35d07f",
        inferred: "#f4c95d",
        missing: "#ef6262"
    };

    const stateDash = {
        recovered: "0",
        inferred: "7 8",
        missing: "2 6"
    };

    const nodeMap = new Map();
    fragments.forEach((fragment) => nodeMap.set(fragment.id, fragment));

    svg.innerHTML = "";

    const ns = "http://www.w3.org/2000/svg";

    fragments.forEach((fragment) => {
        fragment.connections.forEach((targetId) => {
            const target = nodeMap.get(targetId);
            if (!target) return;

            const line = document.createElementNS(ns, "line");
            const strokeColor = stateColors[fragment.state] || stateColors.inferred;
            line.setAttribute("x1", fragment.x);
            line.setAttribute("y1", fragment.y);
            line.setAttribute("x2", target.x);
            line.setAttribute("y2", target.y);
            line.setAttribute("stroke", strokeColor);
            line.setAttribute("stroke-width", fragment.state === "missing" ? "1.8" : "2.6");
            line.setAttribute("stroke-dasharray", stateDash[fragment.state] || stateDash.inferred);
            line.setAttribute("stroke-linecap", "round");
            line.setAttribute("opacity", fragment.state === "missing" ? "0.8" : "0.95");
            svg.appendChild(line);
        });
    });

    fragments.forEach((fragment) => {
        const group = document.createElementNS(ns, "g");
        group.setAttribute("class", "fragment-node");
        group.setAttribute("tabindex", "0");
        group.setAttribute("data-fragment-id", fragment.id);
        group.style.cursor = "pointer";

        const circle = document.createElementNS(ns, "circle");
        circle.setAttribute("cx", fragment.x);
        circle.setAttribute("cy", fragment.y);
        circle.setAttribute("r", 20);
        circle.setAttribute("fill", stateColors[fragment.state] || stateColors.inferred);
        circle.setAttribute("fill-opacity", fragment.state === "missing" ? "0.25" : "0.9");
        circle.setAttribute("stroke", stateColors[fragment.state] || stateColors.inferred);
        circle.setAttribute("stroke-width", "2.5");
        circle.setAttribute("vector-effect", "non-scaling-stroke");

        const text = document.createElementNS(ns, "text");
        text.setAttribute("x", fragment.x);
        text.setAttribute("y", fragment.y + 4);
        text.setAttribute("text-anchor", "middle");
        text.setAttribute("fill", "#edf4ff");
        text.setAttribute("font-size", "11");
        text.setAttribute("font-family", "ui-monospace, SFMono-Regular, Consolas, monospace");
        text.setAttribute("font-weight", "700");
        text.textContent = fragment.id.replace("F", "");

        group.appendChild(circle);
        group.appendChild(text);
        svg.appendChild(group);

        const onSelect = () => updateFragmentDetails(fragment.id);
        group.addEventListener("click", onSelect);
        group.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onSelect();
            }
        });
    });
}

function updateFragmentDetails(fragmentId) {
    const fragment = state.fragments.find((item) => item.id === fragmentId);
    if (!fragment) return;

    state.selectedFragment = fragment;

    const stateLabel = {
        recovered: "Recovered",
        inferred: "AI Inference",
        missing: "Missing / Unknown"
    }[fragment.state] || "Unknown";

    const idLabel = document.getElementById("fragmentIdLabel");
    const artifactLabel = document.getElementById("fragmentArtifact");
    const typeLabel = document.getElementById("fragmentType");
    const compatLabel = document.getElementById("fragmentCompat");
    const stateLabelNode = document.getElementById("fragmentState");
    const hashLabel = document.getElementById("fragmentHash");
    const reasoning = document.getElementById("fragmentReasoning");

    if (idLabel) idLabel.textContent = fragment.id;
    if (artifactLabel) artifactLabel.textContent = fragment.artifact;
    if (typeLabel) typeLabel.textContent = fragment.type;
    if (compatLabel) compatLabel.textContent = fragment.compatibility.toFixed(2);
    if (stateLabelNode) stateLabelNode.textContent = stateLabel;
    if (hashLabel) hashLabel.textContent = fragment.hashStatus;
    if (reasoning) reasoning.textContent = fragment.reasoning;

    document.querySelectorAll(".fragment-node").forEach((node) => {
        const circle = node.querySelector("circle");
        if (!circle) return;
        const selected = node.dataset.fragmentId === fragmentId;
        circle.setAttribute("stroke-width", selected ? "4" : "2.5");
        circle.setAttribute("r", selected ? "22" : "20");
        node.setAttribute("aria-selected", selected ? "true" : "false");
    });
}

function openArtifactModal(artifact) {
    const modal = document.getElementById("artifactModal");
    if (!modal) return;

    const modalTitle = document.getElementById("artifactModalTitle");
    const modalType = document.getElementById("modalArtifactType");
    const modalRecovery = document.getElementById("modalArtifactRecovery");
    const modalState = document.getElementById("modalArtifactState");
    const modalIntegrityValue = document.getElementById("modalIntegrityValue");
    const modalCorruptionValue = document.getElementById("modalCorruptionValue");
    const integrityBar = document.getElementById("modalIntegrityBar");
    const corruptionBar = document.getElementById("modalCorruptionBar");
    const aiExplanation = document.getElementById("modalAiExplanation");
    const explainabilityList = document.getElementById("explainabilityList");

    if (modalTitle) modalTitle.textContent = artifact.name;
    if (modalType) modalType.textContent = artifact.type;
    if (modalRecovery) modalRecovery.textContent = `${artifact.recovery}%`;
    if (modalState) modalState.textContent = artifact.state;
    if (modalIntegrityValue) modalIntegrityValue.textContent = `${artifact.integrity}%`;
    if (modalCorruptionValue) modalCorruptionValue.textContent = `${artifact.corruption}%`;
    if (integrityBar) integrityBar.style.width = `${artifact.integrity}%`;
    if (corruptionBar) corruptionBar.style.width = `${artifact.corruption}%`;
    if (aiExplanation) aiExplanation.textContent = artifact.explanation;

    if (explainabilityList) {
        explainabilityList.innerHTML = (artifact.explainability || [])
            .map((item) => `<li>${item}</li>`)
            .join("");
    }

    modal.classList.add("is-open");
    modal.setAttribute("aria-hidden", "false");
}

function closeArtifactModal() {
    const modal = document.getElementById("artifactModal");
    if (!modal) return;
    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
}

function exportEvidenceReport() {
    const payload = {
        generatedAt: new Date().toISOString(),
        mode: state.mode,
        case: state.case,
        stats: state.stats,
        artifacts: state.artifacts,
        fragments: state.fragments,
        timeline: state.timeline,
        audit: state.audit
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "anvaya-evidence-report.json";
    link.click();
    URL.revokeObjectURL(url);
}

function setupSectionNavigation() {
    const links = [...document.querySelectorAll(".section-nav a")];
    const sections = links
        .map((link) => document.querySelector(link.getAttribute("href")))
        .filter(Boolean);

    if (!links.length || !sections.length || !("IntersectionObserver" in window)) return;

    const updateActiveLink = (sectionId) => {
        links.forEach((link) => {
            const active = link.getAttribute("href") === `#${sectionId}`;
            link.classList.toggle("active", active);
            if (active) link.setAttribute("aria-current", "location");
            else link.removeAttribute("aria-current");
        });
    };

    const observer = new IntersectionObserver((entries) => {
        const visible = entries
            .filter((entry) => entry.isIntersecting)
            .sort((first, second) => second.intersectionRatio - first.intersectionRatio)[0];

        if (visible) updateActiveLink(visible.target.id);
    }, { rootMargin: "-76px 0px -55% 0px", threshold: [0.15, 0.4, 0.7] });

    sections.forEach((section) => observer.observe(section));
}

async function initializeDashboard() {
    apiRequestFailed = false;
    renderModeIndicator();

    try {
        const [caseResponse, artifactsResponse, fragmentsResponse, timelineResponse, auditResponse] = await Promise.all([
            fetchCaseData(),
            fetchArtifacts(),
            fetchFragments(),
            fetchTimeline(),
            fetchAuditData()
        ]);

        if (apiRequestFailed) {
            throw new Error("One or more backend requests failed");
        }

        state.mode = "live";
        state.case = normalizeCase(caseResponse);
        state.stats = state.case.stats;
        state.artifacts = (Array.isArray(artifactsResponse) ? artifactsResponse : artifactsResponse?.artifacts || []).map(normalizeArtifact);
        state.fragments = (Array.isArray(fragmentsResponse) ? fragmentsResponse : fragmentsResponse?.fragments || []).map(normalizeFragment);
        state.timeline = (Array.isArray(timelineResponse) ? timelineResponse : timelineResponse?.timeline || []).map(normalizeTimeline);
        state.audit = normalizeAudit(auditResponse);
    } catch (error) {
        console.warn("FastAPI unavailable; loading demonstration dataset.", error);
        state.mode = "demo";
        state.case = normalizeCase(mockCaseResponse());
        state.stats = state.case.stats;
        state.artifacts = MOCK_DATA.artifacts.map(normalizeArtifact);
        state.fragments = MOCK_DATA.fragments.map(normalizeFragment);
        state.timeline = MOCK_DATA.timeline.map(normalizeTimeline);
        state.audit = normalizeAudit(mockAuditResponse());
    }

    renderModeIndicator();
    renderCase();
    renderAudit();
    renderStats(state.stats);
    renderArtifactTable(state.artifacts);
    renderTimeline(state.timeline);
    renderFragmentGraph(state.fragments);
    updateFragmentDetails(state.fragments.find((fragment) => fragment.id === "F007")?.id || state.fragments[0]?.id || "F007");
    setupSectionNavigation();

    const exportBtn = document.getElementById("exportReportBtn");
    if (exportBtn) exportBtn.addEventListener("click", exportEvidenceReport);

    const modal = document.getElementById("artifactModal");
    const closeBtn = document.getElementById("closeArtifactModal");

    if (closeBtn) closeBtn.addEventListener("click", closeArtifactModal);
    if (modal) {
        modal.addEventListener("click", (event) => {
            if (event.target === modal) closeArtifactModal();
        });
    }
}

document.addEventListener("DOMContentLoaded", initializeDashboard);