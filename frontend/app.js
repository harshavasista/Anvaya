const API_CONFIG = {
    baseUrl: "http://127.0.0.1:8000/api",
    timeout: 120000,
    endpoints: {
        analyze: "/case/analyze"
    }
};

const state = {
    mode: "demo",
    case: null,
    stats: null,
    artifacts: [],
    fragments: [],
    timeline: [],
    audit: null,
    selectedFragment: null,
    selectedArtifact: null,
    rawResponse: null
};

let apiRequestFailed = false;


/* =========================================================
   DEMO DATA
========================================================= */

const MOCK_DATA = {
    caseInfo: {
        id: "CASE-2026-001",
        evidenceId: "EVC-18-421",
        sha256:
            "a9d3c1ae6f3d0b4a93d4ba3586f61e9a5d0e9b827a5d3273b09f0af1c9d7ee93",
        inputTimestamp: "2026-09-21 09:42 UTC",
        processingTimestamp: "2026-09-22 14:11 UTC",
        operationCount: 7,
        originalHash:
            "66fb4a6df0cb9ce9855020d4f5c9d456a8d6bf5a8a3db1763f6780aefaf7d8b9",
        recoveredArtifactHash:
            "4a1c9ab1c0ef85ea4be0b8e1f49cb1dbd2db94cb1c2710a7d198e8022c8d3431",
        provenanceStatus: "Tamper-evident audit recorded"
    },

    stats: {
        fileCount: 1,
        recovered: 91,
        confidence: 0,
        totalFragments: 79,
        inferred: 0,
        missing: 5
    },

    artifacts: [
        {
            name: "Evidence File",
            type: "PDF",
            recovery: 91,
            integrity: 91,
            corruption: 9,
            state: "partial",
            explanation:
                "The evidence file was divided into fragments and analyzed for integrity, corruption and reconstruction.",
            explainability: [
                "SHA-256 hash calculated during evidence ingestion.",
                "Fragments were compared against the original fragment sequence.",
                "Missing and corrupted regions were identified.",
                "A reconstruction candidate was generated where surviving evidence was available."
            ]
        }
    ],

    fragments: [
        {
            id: "F001",
            artifact: "Evidence File",
            type: "Recovered Fragment",
            state: "recovered",
            compatibility: 1,
            hashStatus: "Verified",
            reasoning: "Fragment matched the original evidence fragment by SHA-256.",
            connections: [],
            x: 90,
            y: 150
        }
    ],

    timeline: [
        {
            time: "--:--",
            operation: "Evidence analysis",
            status: "success",
            explanation: "Demo evidence analysis."
        }
    ]
};


/* =========================================================
   HELPERS
========================================================= */

function endpointUrl(endpoint) {
    return `${API_CONFIG.baseUrl}${endpoint}`;
}

function shortenHash(hash) {
    if (!hash) return "—";

    if (hash.length <= 18) {
        return hash;
    }

    return `${hash.slice(0, 10)}…${hash.slice(-6)}`;
}

function formatTimestamp(timestamp) {
    if (!timestamp) return "—";

    try {
        const date = new Date(timestamp);

        if (Number.isNaN(date.getTime())) {
            return timestamp;
        }

        return date.toLocaleString();
    } catch {
        return timestamp;
    }
}

function percentage(value) {
    const number = Number(value);

    if (!Number.isFinite(number)) {
        return 0;
    }

    return Math.max(0, Math.min(100, number));
}


/* =========================================================
   BACKEND REQUEST
========================================================= */

async function analyzeEvidenceFile(file) {

    const controller = new AbortController();

    const timeoutId = setTimeout(
        () => controller.abort(),
        API_CONFIG.timeout
    );

    try {

        const formData = new FormData();

        formData.append("file", file);

        const response = await fetch(
            endpointUrl(API_CONFIG.endpoints.analyze),
            {
                method: "POST",
                body: formData,
                signal: controller.signal
            }
        );

        if (!response.ok) {
            const errorText = await response.text();

            throw new Error(
                `Backend returned HTTP ${response.status}: ${errorText}`
            );
        }

        return await response.json();

    } finally {

        clearTimeout(timeoutId);

    }
}


/* =========================================================
   RESPONSE NORMALIZATION
========================================================= */

function normalizeBackendResponse(response) {

    const caseData = response?.case || {};
    const evidence = response?.evidence || {};
    const fragmentAnalysis = response?.fragment_analysis || {};
    const integrity = response?.integrity || {};
    const corruption = response?.corruption || {};
    const aiAnalysis = response?.ai_analysis || {};
    const reconstruction = response?.reconstruction || {};
    const audit = response?.audit || {};

    const reconstructionReport =
        reconstruction.report || {};

    const corruptionSummary =
        corruption.summary || {};

    const aiSummary =
        aiAnalysis.summary || {};

    const totalFragments =
        Number(
            fragmentAnalysis.total_fragments ||
            reconstructionReport.total_original_fragments ||
            0
        );

    const recoveredFragments =
        Number(
            reconstructionReport.recovered_fragments ||
            corruptionSummary.intact_fragments ||
            0
        );

    const missingFragments =
        Number(
            reconstructionReport.missing_fragments ||
            corruptionSummary.missing_fragments ||
            0
        );

    const corruptedFragments =
        Number(
            corruptionSummary.corrupted_fragments ||
            0
        );

    const coverage =
        Number(
            corruptionSummary.coverage_percentage ??
            (
                totalFragments
                    ? ((recoveredFragments + corruptedFragments) /
                        totalFragments) * 100
                    : 0
            )
        );

    const intactPercentage =
        Number(
            corruptionSummary.intact_percentage ??
            (
                totalFragments
                    ? (recoveredFragments / totalFragments) * 100
                    : 0
            )
        );

    const anomalyFragments =
        Number(
            aiSummary.fragments_analyzed ||
            0
        );

    /*
     * The current backend uses heuristic anomaly analysis.
     * Therefore we do NOT invent an AI confidence value.
     */
    const aiConfidence = 0;

    return {

        caseInfo: {
            id: caseData.case_id || "UNKNOWN",
            evidenceId: evidence.filename || "UNKNOWN",
            sha256: evidence.sha256 || "",
            inputTimestamp: caseData.created_at || "",
            processingTimestamp: audit.created_at || caseData.created_at || "",
            operationCount: Number(audit.event_count || 0),
            originalHash: evidence.sha256 || "",
            recoveredArtifactHash:
                reconstruction.candidate?.sha256 || "",
            provenanceStatus:
                audit.status === "audit_log_created"
                    ? "Tamper-evident audit recorded"
                    : "Audit unavailable"
        },

        stats: {
            fileCount: 1,
            recovered: Math.round(intactPercentage),
            confidence: aiConfidence,
            totalFragments,
            inferred: 0,
            missing:
                totalFragments
                    ? Math.round(
                        (missingFragments / totalFragments) * 100
                    )
                    : 0
        },

        artifacts: [
            {
                name: evidence.filename || "Evidence File",
                type: evidence.file_type || "Unknown",
                recovery: Math.round(intactPercentage),
                integrity: Math.round(intactPercentage),
                corruption:
                    totalFragments
                        ? Math.round(
                            ((corruptedFragments + missingFragments) /
                                totalFragments) * 100
                        )
                        : 0,
                state:
                    missingFragments === 0 &&
                    corruptedFragments === 0
                        ? "recovered"
                        : "partial",

                explanation:
                    "Anvaya analyzed the evidence using fragment integrity, corruption comparison, anomaly analysis and reconstruction mapping.",

                explainability: [
                    `Evidence SHA-256: ${evidence.sha256 || "Unavailable"}.`,
                    `Total fragments analyzed: ${totalFragments}.`,
                    `Intact fragments: ${recoveredFragments}.`,
                    `Corrupted fragments: ${corruptedFragments}.`,
                    `Missing fragments: ${missingFragments}.`,
                    `Evidence coverage: ${coverage.toFixed(2)}%.`,
                    `Anomaly analysis completed on ${anomalyFragments} fragments.`,
                    reconstruction.candidate
                        ? "A partial reconstruction candidate was generated."
                        : "No reconstruction candidate was generated."
                ]
            }
        ],

        fragments: buildFrontendFragments(
            reconstruction.map || [],
            evidence.filename || "Evidence File"
        ),

        timeline: buildTimeline(response),

        audit: {
            caseId: caseData.case_id || "",
            evidenceId: evidence.filename || "",
            sha256: evidence.sha256 || "",
            inputTimestamp: caseData.created_at || "",
            processingTimestamp:
                audit.created_at ||
                caseData.created_at ||
                "",
            operationCount:
                Number(audit.event_count || 0),
            originalHash: evidence.sha256 || "",
            recoveredHash:
                reconstruction.candidate?.sha256 || "",
            provenanceStatus:
                audit.status === "audit_log_created"
                    ? "Tamper-evident audit recorded"
                    : "Unknown"
        },

        raw: response
    };
}


/* =========================================================
   BUILD FRONTEND FRAGMENTS
========================================================= */

function buildFrontendFragments(
    reconstructionMap,
    artifactName
) {

    if (!Array.isArray(reconstructionMap)) {
        return [];
    }

    const fragments = reconstructionMap.map(
        (item, index) => {

            let stateValue = "missing";

            if (item.status === "RECOVERED") {
                stateValue = "recovered";
            } else if (item.status === "CORRUPTED") {
                stateValue = "inferred";
            } else if (item.status === "MISSING") {
                stateValue = "missing";
            }

            let hashStatus = "Unknown";

            if (item.status === "RECOVERED") {
                hashStatus = "Verified";
            } else if (item.status === "CORRUPTED") {
                hashStatus = "Corrupted";
            } else if (item.status === "MISSING") {
                hashStatus = "Missing";
            }

            let reasoning =
                "No additional fragment reasoning was supplied.";

            if (item.status === "RECOVERED") {

                reasoning =
                    "The surviving fragment matched the original fragment by SHA-256.";

            } else if (item.status === "CORRUPTED") {

                reasoning =
                    `${item.changed_bytes || 0} changed byte(s) were detected in this fragment.`;

            } else if (item.status === "MISSING") {

                reasoning =
                    "No surviving physical fragment was matched to this original position.";

            }

            return {
                id: `F${String(index + 1).padStart(3, "0")}`,
                artifact: artifactName,
                type:
                    item.status === "RECOVERED"
                        ? "Recovered Fragment"
                        : item.status === "CORRUPTED"
                            ? "Corrupted Fragment"
                            : "Missing Fragment",

                state: stateValue,

                compatibility:
                    item.status === "RECOVERED"
                        ? 1
                        : item.status === "CORRUPTED"
                            ? 0.5
                            : 0,

                hashStatus,

                reasoning,

                connections: [],

                originalIndex: item.original_index,
                filename: item.filename,
                sha256: item.sha256,
                size: item.size,
                changedBytes: item.changed_bytes || 0,

                x: 70 + (index % 6) * 115,
                y: 70 + Math.floor(index / 6) * 70
            };
        }
    );

    /*
     * Connect consecutive fragments only to visualize
     * reconstruction order.
     *
     * This is NOT an AI-inferred relationship.
     */
    fragments.forEach(
        (fragment, index) => {

            if (index < fragments.length - 1) {

                fragment.connections = [
                    fragments[index + 1].id
                ];

            }

        }
    );

    return fragments;
}


/* =========================================================
   BUILD TIMELINE
========================================================= */

function buildTimeline(response) {

    const caseData = response?.case || {};
    const evidence = response?.evidence || {};
    const fragmentAnalysis =
        response?.fragment_analysis || {};

    const integrity =
        response?.integrity || {};

    const corruption =
        response?.corruption || {};

    const ai =
        response?.ai_analysis || {};

    const reconstruction =
        response?.reconstruction || {};

    const audit =
        response?.audit || {};

    const events = [];

    events.push({
        time: formatTimestamp(caseData.created_at),
        operation: "Case created",
        status: "success",
        explanation:
            `Created case ${caseData.case_id || "unknown"}.`
    });

    events.push({
        time: formatTimestamp(caseData.created_at),
        operation: "Evidence ingestion",
        status: "success",
        explanation:
            `Evidence ${evidence.filename || "file"} was ingested and hashed.`
    });

    events.push({
        time: formatTimestamp(caseData.created_at),
        operation: "Fragment analysis",
        status: "success",
        explanation:
            `${fragmentAnalysis.total_fragments || 0} fragments were analyzed.`
    });

    if (integrity) {

        events.push({
            time: formatTimestamp(caseData.created_at),
            operation: "Integrity analysis",
            status: "success",
            explanation:
                "Fragment integrity and duplicate analysis completed."
        });

    }

    if (corruption?.summary) {

        events.push({
            time: formatTimestamp(caseData.created_at),
            operation: "Corruption analysis",
            status:
                Number(corruption.summary.corrupted_fragments || 0) > 0
                    ? "warning"
                    : "success",

            explanation:
                `${corruption.summary.corrupted_fragments || 0} corrupted and ${corruption.summary.missing_fragments || 0} missing fragment(s) detected.`
        });

    }

    if (ai?.summary) {

        events.push({
            time: formatTimestamp(caseData.created_at),
            operation: "AI anomaly analysis",
            status: "success",
            explanation:
                `Explainable heuristic analysis completed on ${ai.summary.fragments_analyzed || 0} fragments.`
        });

    }

    if (reconstruction?.candidate) {

        events.push({
            time: formatTimestamp(caseData.created_at),
            operation: "Reconstruction candidate generated",
            status: "warning",
            explanation:
                "A partial reconstruction candidate was generated from surviving evidence."
        });

    }

    if (audit?.event_count) {

        events.push({
            time: formatTimestamp(caseData.created_at),
            operation: "Audit log created",
            status: "success",
            explanation:
                `${audit.event_count} audit event(s) were recorded.`
        });

    }

    return events;
}


/* =========================================================
   DEMO RESPONSES
========================================================= */

function mockResponse() {

    return {
        case: {
            case_id: MOCK_DATA.caseInfo.id,
            created_at: MOCK_DATA.caseInfo.processingTimestamp,
            status: "analysis_complete"
        },

        evidence: {
            filename: "demo-evidence.pdf",
            file_type: "PDF",
            size_bytes: 321520,
            sha256: MOCK_DATA.caseInfo.sha256
        },

        fragment_analysis: {
            total_fragments: 79,
            fragment_size: 4096
        },

        integrity: {
            original_fragments: 79,
            physical_fragments: 76,
            unique_fragments: 74,
            duplicate_groups: 2,
            duplicate_files: 4,
            missing_estimate: 5,
            coverage_percentage: 93.67
        },

        corruption: {
            summary: {
                original_fragments: 79,
                intact_fragments: 72,
                corrupted_fragments: 2,
                missing_fragments: 5,
                total_changed_bytes: 19,
                coverage_percentage: 93.67,
                intact_percentage: 91.14
            },

            fragments: []
        },

        ai_analysis: {
            method:
                "Explainable AI-assisted heuristic analysis",

            summary: {
                fragments_analyzed: 76,
                normal: 76,
                suspicious: 0,
                high_anomaly: 0,
                analysis_errors: 0
            },

            fragments: []
        },

        reconstruction: {
            status: "candidate_generated",

            report: {
                total_original_fragments: 79,
                recovered_fragments: 72,
                missing_fragments: 5,
                fragment_coverage_percentage: 91.14
            },

            candidate: {
                filename:
                    "CASE-2026-001_reconstruction_candidate.bin",

                status: "CANDIDATE_ONLY",

                total_bytes: 321520,
                recovered_bytes: 303104,
                missing_bytes: 18416,
                recovery_percentage: 94.27,

                sha256:
                    MOCK_DATA.caseInfo.recoveredArtifactHash
            },

            map: []
        },

        audit: {
            status: "audit_log_created",
            audit_sha256:
                "267fd83cfeaaad1fb8fbf5d8d00b0100cabb553bbeab9905046e39a882de7fb5",
            event_count: 7
        }
    };
}


/* =========================================================
   MODE INDICATOR
========================================================= */

function renderModeIndicator() {

    const indicator =
        document.getElementById("modeIndicator");

    const label =
        document.getElementById("modeLabel");

    const note =
        document.getElementById("connectionNote");

    const dataSourceNote =
        document.getElementById("dataSourceNote");

    if (!indicator || !label) return;

    indicator.dataset.mode = state.mode;

    if (state.mode === "live") {

        label.textContent = "LIVE BACKEND";

        if (note) {
            note.textContent =
                "Connected to the FastAPI forensic engine.";
        }

        if (dataSourceNote) {
            dataSourceNote.textContent =
                "Live API data";
        }

    } else if (state.mode === "demo") {

        label.textContent = "DEMO MODE";

        if (note) {
            note.textContent =
                "Backend unavailable - using demonstration dataset.";
        }

        if (dataSourceNote) {
            dataSourceNote.textContent =
                "Mock / demo data";
        }

    } else {

        label.textContent =
            "CONNECTING TO FORENSIC ENGINE...";

        if (note) {
            note.textContent =
                "Loading evidence...";
        }

        if (dataSourceNote) {
            dataSourceNote.textContent =
                "Loading data";
        }
    }
}


/* =========================================================
   CASE META
========================================================= */

function renderCaseMeta(caseInfo, audit) {

    const label =
        document.getElementById("caseIdLabel");

    if (label) {
        label.textContent =
            caseInfo?.id || "UNKNOWN";
    }

    const auditCase =
        document.getElementById("auditCaseId");

    const evidenceId =
        document.getElementById("auditEvidenceId");

    const auditHash =
        document.getElementById("auditHash");

    const inputTime =
        document.getElementById("auditInputTime");

    const processTime =
        document.getElementById("auditProcessTime");

    const opCount =
        document.getElementById("auditOps");

    const originalHash =
        document.getElementById("auditOriginalHash");

    const recoveredHash =
        document.getElementById("auditRecoveredHash");

    const provenance =
        document.getElementById("auditProvenance");

    const auditData = audit || {};

    if (auditCase) {
        auditCase.textContent =
            auditData.caseId ||
            caseInfo?.id ||
            "—";
    }

    if (evidenceId) {
        evidenceId.textContent =
            auditData.evidenceId ||
            "—";
    }

    if (auditHash) {
        auditHash.textContent =
            shortenHash(auditData.sha256);
    }

    if (inputTime) {
        inputTime.textContent =
            formatTimestamp(
                auditData.inputTimestamp
            );
    }

    if (processTime) {
        processTime.textContent =
            formatTimestamp(
                auditData.processingTimestamp
            );
    }

    if (opCount) {
        opCount.textContent =
            auditData.operationCount || 0;
    }

    if (originalHash) {
        originalHash.textContent =
            shortenHash(auditData.originalHash);
    }

    if (recoveredHash) {
        recoveredHash.textContent =
            shortenHash(auditData.recoveredHash);
    }

    if (provenance) {
        provenance.textContent =
            auditData.provenanceStatus ||
            "Unknown";
    }
}


/* =========================================================
   CASE / AUDIT
========================================================= */

function renderCase() {

    renderCaseMeta(
        state.case,
        state.audit
    );
}

function renderAudit() {

    renderCaseMeta(
        state.case,
        state.audit
    );
}


/* =========================================================
   STATISTICS
========================================================= */

function renderStats(stats) {

    const map = {

        fileCount:
            document.getElementById("fileCount"),

        recoveredCount:
            document.getElementById("recoveredCount"),

        confidence:
            document.getElementById("confidence"),

        fragmentCount:
            document.getElementById("fragmentCount"),

        recoveredMetric:
            document.getElementById("recoveredMetric"),

        inferredMetric:
            document.getElementById("inferredMetric"),

        missingMetric:
            document.getElementById("missingMetric"),

        recoveredMetricBar:
            document.getElementById("recoveredMetricBar"),

        inferredMetricBar:
            document.getElementById("inferredMetricBar"),

        missingMetricBar:
            document.getElementById("missingMetricBar")
    };

    if (map.fileCount) {
        map.fileCount.textContent =
            Number(stats.fileCount || 0).toLocaleString();
    }

    if (map.recoveredCount) {
        map.recoveredCount.textContent =
            `${percentage(stats.recovered)}%`;
    }

    if (map.confidence) {

        if (Number(stats.confidence) > 0) {

            map.confidence.textContent =
                `${percentage(stats.confidence)}%`;

        } else {

            map.confidence.textContent =
                "N/A";
        }
    }

    if (map.fragmentCount) {
        map.fragmentCount.textContent =
            Number(stats.totalFragments || 0).toLocaleString();
    }

    if (map.recoveredMetric) {
        map.recoveredMetric.textContent =
            `${percentage(stats.recovered)}%`;
    }

    if (map.inferredMetric) {
        map.inferredMetric.textContent =
            `${percentage(stats.inferred)}%`;
    }

    if (map.missingMetric) {
        map.missingMetric.textContent =
            `${percentage(stats.missing)}%`;
    }

    if (map.recoveredMetricBar) {
        map.recoveredMetricBar.style.width =
            `${percentage(stats.recovered)}%`;
    }

    if (map.inferredMetricBar) {
        map.inferredMetricBar.style.width =
            `${percentage(stats.inferred)}%`;
    }

    if (map.missingMetricBar) {
        map.missingMetricBar.style.width =
            `${percentage(stats.missing)}%`;
    }
}


/* =========================================================
   ARTIFACT TABLE
========================================================= */

function renderArtifactTable(artifacts) {

    const tableBody =
        document.getElementById(
            "artifactTableBody"
        );

    if (!tableBody) return;

    tableBody.innerHTML =
        artifacts
            .map((artifact) => {

                const stateClass =
                    artifact.state === "recovered"
                        ? "recovered"
                        : artifact.state === "partial"
                            ? "partial"
                            : "missing";

                const recoveryValue =
                    artifact.recovery ??
                    artifact.integrity ??
                    0;

                return `
                    <div
                        class="artifact-row"
                        data-artifact-name="${escapeHtml(
                            artifact.name
                        )}"
                    >

                        <span class="artifact-name">
                            ${escapeHtml(artifact.name)}
                        </span>

                        <span class="artifact-type">
                            ${escapeHtml(artifact.type)}
                        </span>

                        <span class="artifact-recovery">
                            ${recoveryValue}%
                        </span>

                        <span class="badge ${stateClass}">
                            ${escapeHtml(artifact.state)}
                        </span>

                    </div>
                `;
            })
            .join("");

    tableBody
        .querySelectorAll(".artifact-row")
        .forEach((row) => {

            row.addEventListener(
                "click",
                () => {

                    const name =
                        row.dataset.artifactName;

                    const artifact =
                        artifacts.find(
                            (item) =>
                                item.name === name
                        );

                    if (artifact) {

                        state.selectedArtifact =
                            artifact;

                        openArtifactModal(
                            artifact
                        );
                    }
                }
            );
        });
}


/* =========================================================
   TIMELINE
========================================================= */

function renderTimeline(events) {

    const timelineList =
        document.getElementById(
            "timelineList"
        );

    if (!timelineList) return;

    timelineList.innerHTML =
        events
            .map((event) => {

                const statusClass = {

                    success: "success",
                    warning: "warning",
                    muted: "muted"

                }[
                    event.status
                ] || "muted";

                return `
                    <div class="timeline-event">

                        <div class="timeline-time">
                            ${escapeHtml(event.time)}
                        </div>

                        <div class="timeline-copy">

                            <strong>
                                ${escapeHtml(event.operation)}
                            </strong>

                            <span>
                                ${escapeHtml(event.explanation)}
                            </span>

                        </div>

                        <div class="timeline-status ${statusClass}">
                            ${escapeHtml(event.status)}
                        </div>

                    </div>
                `;
            })
            .join("");
}


/* =========================================================
   FRAGMENT GRAPH
========================================================= */

function renderFragmentGraph(fragments) {

    const svg =
        document.getElementById(
            "fragmentGraph"
        );

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

    fragments.forEach(
        (fragment) =>
            nodeMap.set(
                fragment.id,
                fragment
            )
    );

    svg.innerHTML = "";

    const ns =
        "http://www.w3.org/2000/svg";

    /*
     * Draw reconstruction-order connections.
     */
    fragments.forEach(
        (fragment) => {

            fragment.connections.forEach(
                (targetId) => {

                    const target =
                        nodeMap.get(targetId);

                    if (!target) return;

                    const line =
                        document.createElementNS(
                            ns,
                            "line"
                        );

                    const strokeColor =
                        stateColors[
                            fragment.state
                        ] ||
                        stateColors.inferred;

                    line.setAttribute(
                        "x1",
                        fragment.x
                    );

                    line.setAttribute(
                        "y1",
                        fragment.y
                    );

                    line.setAttribute(
                        "x2",
                        target.x
                    );

                    line.setAttribute(
                        "y2",
                        target.y
                    );

                    line.setAttribute(
                        "stroke",
                        strokeColor
                    );

                    line.setAttribute(
                        "stroke-width",
                        "2.2"
                    );

                    line.setAttribute(
                        "stroke-dasharray",
                        stateDash[
                            fragment.state
                        ] ||
                        stateDash.inferred
                    );

                    line.setAttribute(
                        "stroke-linecap",
                        "round"
                    );

                    line.setAttribute(
                        "opacity",
                        "0.8"
                    );

                    svg.appendChild(line);
                }
            );
        }
    );


    /*
     * Draw fragment nodes.
     */
    fragments.forEach(
        (fragment) => {

            const group =
                document.createElementNS(
                    ns,
                    "g"
                );

            group.setAttribute(
                "class",
                "fragment-node"
            );

            group.setAttribute(
                "tabindex",
                "0"
            );

            group.setAttribute(
                "data-fragment-id",
                fragment.id
            );

            group.style.cursor =
                "pointer";

            const circle =
                document.createElementNS(
                    ns,
                    "circle"
                );

            circle.setAttribute(
                "cx",
                fragment.x
            );

            circle.setAttribute(
                "cy",
                fragment.y
            );

            circle.setAttribute(
                "r",
                "18"
            );

            const color =
                stateColors[
                    fragment.state
                ] ||
                stateColors.inferred;

            circle.setAttribute(
                "fill",
                color
            );

            circle.setAttribute(
                "fill-opacity",
                fragment.state === "missing"
                    ? "0.25"
                    : "0.9"
            );

            circle.setAttribute(
                "stroke",
                color
            );

            circle.setAttribute(
                "stroke-width",
                "2.5"
            );

            const text =
                document.createElementNS(
                    ns,
                    "text"
                );

            text.setAttribute(
                "x",
                fragment.x
            );

            text.setAttribute(
                "y",
                fragment.y + 4
            );

            text.setAttribute(
                "text-anchor",
                "middle"
            );

            text.setAttribute(
                "fill",
                "#edf4ff"
            );

            text.setAttribute(
                "font-size",
                "9"
            );

            text.setAttribute(
                "font-family",
                "ui-monospace, SFMono-Regular, Consolas, monospace"
            );

            text.setAttribute(
                "font-weight",
                "700"
            );

            text.textContent =
                fragment.id.replace(
                    "F",
                    ""
                );

            group.appendChild(circle);
            group.appendChild(text);

            svg.appendChild(group);

            const onSelect =
                () =>
                    updateFragmentDetails(
                        fragment.id
                    );

            group.addEventListener(
                "click",
                onSelect
            );

            group.addEventListener(
                "keydown",
                (event) => {

                    if (
                        event.key === "Enter" ||
                        event.key === " "
                    ) {

                        event.preventDefault();

                        onSelect();
                    }
                }
            );
        }
    );
}


/* =========================================================
   FRAGMENT DETAILS
========================================================= */

function updateFragmentDetails(fragmentId) {

    const fragment =
        state.fragments.find(
            (item) =>
                item.id === fragmentId
        );

    if (!fragment) return;

    state.selectedFragment =
        fragment;

    const stateLabel = {

        recovered: "Recovered",

        inferred:
            "Corrupted / Requires Review",

        missing:
            "Missing / Unknown"

    }[
        fragment.state
    ] || "Unknown";


    const idLabel =
        document.getElementById(
            "fragmentIdLabel"
        );

    const artifactLabel =
        document.getElementById(
            "fragmentArtifact"
        );

    const typeLabel =
        document.getElementById(
            "fragmentType"
        );

    const compatLabel =
        document.getElementById(
            "fragmentCompat"
        );

    const stateLabelNode =
        document.getElementById(
            "fragmentState"
        );

    const hashLabel =
        document.getElementById(
            "fragmentHash"
        );

    const reasoning =
        document.getElementById(
            "fragmentReasoning"
        );


    if (idLabel) {
        idLabel.textContent =
            fragment.id;
    }

    if (artifactLabel) {
        artifactLabel.textContent =
            fragment.artifact;
    }

    if (typeLabel) {
        typeLabel.textContent =
            fragment.type;
    }

    if (compatLabel) {
        compatLabel.textContent =
            Number(
                fragment.compatibility
            ).toFixed(2);
    }

    if (stateLabelNode) {
        stateLabelNode.textContent =
            stateLabel;
    }

    if (hashLabel) {
        hashLabel.textContent =
            fragment.hashStatus;
    }

    if (reasoning) {
        reasoning.textContent =
            fragment.reasoning;
    }


    document
        .querySelectorAll(
            ".fragment-node"
        )
        .forEach((node) => {

            const circle =
                node.querySelector(
                    "circle"
                );

            if (!circle) return;

            const selected =
                node.dataset.fragmentId ===
                fragmentId;

            circle.setAttribute(
                "stroke-width",
                selected ? "4" : "2.5"
            );

            circle.setAttribute(
                "r",
                selected ? "21" : "18"
            );

            node.setAttribute(
                "aria-selected",
                selected
                    ? "true"
                    : "false"
            );
        });
}


/* =========================================================
   ARTIFACT MODAL
========================================================= */

function openArtifactModal(artifact) {

    const modal =
        document.getElementById(
            "artifactModal"
        );

    if (!modal) return;

    const modalTitle =
        document.getElementById(
            "artifactModalTitle"
        );

    const modalType =
        document.getElementById(
            "modalArtifactType"
        );

    const modalRecovery =
        document.getElementById(
            "modalArtifactRecovery"
        );

    const modalState =
        document.getElementById(
            "modalArtifactState"
        );

    const modalIntegrityValue =
        document.getElementById(
            "modalIntegrityValue"
        );

    const modalCorruptionValue =
        document.getElementById(
            "modalCorruptionValue"
        );

    const integrityBar =
        document.getElementById(
            "modalIntegrityBar"
        );

    const corruptionBar =
        document.getElementById(
            "modalCorruptionBar"
        );

    const aiExplanation =
        document.getElementById(
            "modalAiExplanation"
        );

    const explainabilityList =
        document.getElementById(
            "explainabilityList"
        );


    if (modalTitle) {
        modalTitle.textContent =
            artifact.name;
    }

    if (modalType) {
        modalType.textContent =
            artifact.type;
    }

    if (modalRecovery) {
        modalRecovery.textContent =
            `${artifact.recovery}%`;
    }

    if (modalState) {
        modalState.textContent =
            artifact.state;
    }

    if (modalIntegrityValue) {
        modalIntegrityValue.textContent =
            `${artifact.integrity}%`;
    }

    if (modalCorruptionValue) {
        modalCorruptionValue.textContent =
            `${artifact.corruption}%`;
    }

    if (integrityBar) {
        integrityBar.style.width =
            `${percentage(artifact.integrity)}%`;
    }

    if (corruptionBar) {
        corruptionBar.style.width =
            `${percentage(artifact.corruption)}%`;
    }

    if (aiExplanation) {
        aiExplanation.textContent =
            artifact.explanation;
    }

    if (explainabilityList) {

        explainabilityList.innerHTML =
            (artifact.explainability || [])
                .map(
                    (item) =>
                        `<li>${escapeHtml(item)}</li>`
                )
                .join("");
    }


    modal.classList.add(
        "is-open"
    );

    modal.setAttribute(
        "aria-hidden",
        "false"
    );
}


function closeArtifactModal() {

    const modal =
        document.getElementById(
            "artifactModal"
        );

    if (!modal) return;

    modal.classList.remove(
        "is-open"
    );

    modal.setAttribute(
        "aria-hidden",
        "true"
    );
}


/* =========================================================
   EXPORT REPORT
========================================================= */

function exportEvidenceReport() {

    const payload = {

        generatedAt:
            new Date().toISOString(),

        mode:
            state.mode,

        case:
            state.case,

        stats:
            state.stats,

        artifacts:
            state.artifacts,

        fragments:
            state.fragments,

        timeline:
            state.timeline,

        audit:
            state.audit,

        backendResponse:
            state.rawResponse
    };


    const blob =
        new Blob(
            [
                JSON.stringify(
                    payload,
                    null,
                    2
                )
            ],
            {
                type:
                    "application/json"
            }
        );

    const url =
        URL.createObjectURL(
            blob
        );

    const link =
        document.createElement(
            "a"
        );

    link.href = url;

    link.download =
        "anvaya-evidence-report.json";

    link.click();

    URL.revokeObjectURL(
        url
    );
}


/* =========================================================
   FILE UPLOAD UI
========================================================= */

function setupEvidenceUpload() {

    const fileInput =
        document.getElementById(
            "evidenceFile"
        );

    const fileName =
        document.getElementById(
            "selectedFileName"
        );

    const analyzeButton =
        document.getElementById(
            "analyzeEvidenceBtn"
        );

    const uploadStatus =
        document.getElementById(
            "uploadStatus"
        );

    if (
        !fileInput ||
        !analyzeButton
    ) {
        return;
    }


    fileInput.addEventListener(
        "change",
        () => {

            const file =
                fileInput.files?.[0];

            if (!file) {

                if (fileName) {
                    fileName.textContent =
                        "No file selected";
                }

                return;
            }

            if (fileName) {
                fileName.textContent =
                    `${file.name} (${formatBytes(file.size)})`;
            }

            if (uploadStatus) {
                uploadStatus.textContent =
                    "File selected. Click Analyze Evidence.";
            }
        }
    );


    analyzeButton.addEventListener(
        "click",
        async () => {

            const file =
                fileInput.files?.[0];

            if (!file) {

                if (uploadStatus) {
                    uploadStatus.textContent =
                        "Please select an evidence file first.";
                }

                return;
            }


            analyzeButton.disabled =
                true;

            analyzeButton.textContent =
                "Analyzing...";


            if (uploadStatus) {
                uploadStatus.textContent =
                    "Uploading evidence and running forensic analysis...";
            }


            try {

                const response =
                    await analyzeEvidenceFile(
                        file
                    );

                const normalized =
                    normalizeBackendResponse(
                        response
                    );

                state.mode =
                    "live";

                state.case =
                    normalized.caseInfo;

                state.stats =
                    normalized.stats;

                state.artifacts =
                    normalized.artifacts;

                state.fragments =
                    normalized.fragments;

                state.timeline =
                    normalized.timeline;

                state.audit =
                    normalized.audit;

                state.rawResponse =
                    normalized.raw;


                renderModeIndicator();

                renderCase();

                renderAudit();

                renderStats(
                    state.stats
                );

                renderArtifactTable(
                    state.artifacts
                );

                renderTimeline(
                    state.timeline
                );

                renderFragmentGraph(
                    state.fragments
                );


                if (
                    state.fragments.length
                ) {

                    updateFragmentDetails(
                        state.fragments[0].id
                    );
                }


                if (uploadStatus) {

                    uploadStatus.textContent =
                        "Analysis completed successfully. Live backend data is displayed.";
                }

                window.location.hash =
                    "overview";

            } catch (error) {

                console.error(
                    "Evidence analysis failed:",
                    error
                );

                state.mode =
                    "demo";

                const mock =
                    normalizeBackendResponse(
                        mockResponse()
                    );

                state.case =
                    mock.caseInfo;

                state.stats =
                    mock.stats;

                state.artifacts =
                    mock.artifacts;

                state.fragments =
                    mock.fragments;

                state.timeline =
                    mock.timeline;

                state.audit =
                    mock.audit;

                state.rawResponse =
                    mock.raw;


                renderModeIndicator();

                renderCase();

                renderAudit();

                renderStats(
                    state.stats
                );

                renderArtifactTable(
                    state.artifacts
                );

                renderTimeline(
                    state.timeline
                );

                renderFragmentGraph(
                    state.fragments
                );


                if (uploadStatus) {

                    uploadStatus.textContent =
                        `Backend analysis failed: ${error.message}`;
                }

            } finally {

                analyzeButton.disabled =
                    false;

                analyzeButton.textContent =
                    "Analyze Evidence";
            }
        }
    );
}


/* =========================================================
   SECTION NAVIGATION
========================================================= */

function setupSectionNavigation() {

    const links =
        [
            ...document.querySelectorAll(
                ".section-nav a"
            )
        ];

    const sections =
        links
            .map(
                (link) =>
                    document.querySelector(
                        link.getAttribute(
                            "href"
                        )
                    )
            )
            .filter(Boolean);


    if (
        !links.length ||
        !sections.length ||
        !(
            "IntersectionObserver"
            in window
        )
    ) {
        return;
    }


    const updateActiveLink =
        (sectionId) => {

            links.forEach(
                (link) => {

                    const active =
                        link.getAttribute(
                            "href"
                        ) ===
                        `#${sectionId}`;

                    link.classList.toggle(
                        "active",
                        active
                    );

                    if (active) {

                        link.setAttribute(
                            "aria-current",
                            "location"
                        );

                    } else {

                        link.removeAttribute(
                            "aria-current"
                        );
                    }
                }
            );
        };


    const observer =
        new IntersectionObserver(
            (entries) => {

                const visible =
                    entries
                        .filter(
                            (entry) =>
                                entry.isIntersecting
                        )
                        .sort(
                            (first, second) =>
                                second.intersectionRatio -
                                first.intersectionRatio
                        )[0];

                if (visible) {

                    updateActiveLink(
                        visible.target.id
                    );
                }
            },
            {
                rootMargin:
                    "-76px 0px -55% 0px",

                threshold: [
                    0.15,
                    0.4,
                    0.7
                ]
            }
        );


    sections.forEach(
        (section) =>
            observer.observe(section)
    );
}


/* =========================================================
   UTILITIES
========================================================= */

function formatBytes(bytes) {

    if (!Number.isFinite(bytes) || bytes <= 0) {
        return "0 B";
    }

    const units = [
        "B",
        "KB",
        "MB",
        "GB"
    ];

    const index =
        Math.floor(
            Math.log(bytes) /
            Math.log(1024)
        );

    const safeIndex =
        Math.min(
            index,
            units.length - 1
        );

    return `${(
        bytes /
        Math.pow(
            1024,
            safeIndex
        )
    ).toFixed(
        safeIndex === 0
            ? 0
            : 2
    )} ${units[safeIndex]}`;
}


function escapeHtml(value) {

    return String(
        value ?? ""
    )
        .replaceAll(
            "&",
            "&amp;"
        )
        .replaceAll(
            "<",
            "&lt;"
        )
        .replaceAll(
            ">",
            "&gt;"
        )
        .replaceAll(
            '"',
            "&quot;"
        )
        .replaceAll(
            "'",
            "&#039;"
        );
}


/* =========================================================
   INITIALIZE
========================================================= */

function loadDemoDashboard() {

    const normalized =
        normalizeBackendResponse(
            mockResponse()
        );

    state.mode =
        "demo";

    state.case =
        normalized.caseInfo;

    state.stats =
        normalized.stats;

    state.artifacts =
        normalized.artifacts;

    state.fragments =
        normalized.fragments;

    state.timeline =
        normalized.timeline;

    state.audit =
        normalized.audit;

    state.rawResponse =
        normalized.raw;


    renderModeIndicator();

    renderCase();

    renderAudit();

    renderStats(
        state.stats
    );

    renderArtifactTable(
        state.artifacts
    );

    renderTimeline(
        state.timeline
    );

    renderFragmentGraph(
        state.fragments
    );

    if (state.fragments.length) {

        updateFragmentDetails(
            state.fragments[0].id
        );
    }
}


function setupModal() {

    const modal =
        document.getElementById(
            "artifactModal"
        );

    const closeBtn =
        document.getElementById(
            "closeArtifactModal"
        );


    if (closeBtn) {

        closeBtn.addEventListener(
            "click",
            closeArtifactModal
        );
    }


    if (modal) {

        modal.addEventListener(
            "click",
            (event) => {

                if (
                    event.target ===
                    modal
                ) {
                    closeArtifactModal();
                }
            }
        );
    }
}


function initializeDashboard() {

    apiRequestFailed = false;

    loadDemoDashboard();

    setupEvidenceUpload();

    setupSectionNavigation();

    setupModal();


    const exportBtn =
        document.getElementById(
            "exportReportBtn"
        );

    if (exportBtn) {

        exportBtn.addEventListener(
            "click",
            exportEvidenceReport
        );
    }
}


document.addEventListener(
    "DOMContentLoaded",
    initializeDashboard
);