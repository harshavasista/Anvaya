const API_CONFIG = {
    baseUrl: "http://127.0.0.1:8000/api",
    timeout: 120000,
    endpoints: {
        analyze: "/case/analyze",
        recover: "/case/recover"
    }
};


/* =========================================================
   GLOBAL STATE
========================================================= */

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
let uploadStatus = null;


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
        evidenceIntegrity: 91,
        observedIntact: 91,
        suspectedAnomalous: 3,
        unknownUnrecoverable: 6,
        anomalyScore: "Normal",
        confidence: "N/A",
        totalFragments: 79
    },

    artifacts: [
        {
            name: "Evidence File",
            type: "PDF",
            evidenceIntegrity: 91,
            observedIntact: 91,
            suspectedAnomalous: 3,
            unknownUnrecoverable: 6,
            state: "observed",

            explanation:
                "The evidence file was divided into fragments and analyzed for integrity, structural consistency, anomalies and observable evidence.",

            explainability: [
                "SHA-256 hash calculated during evidence ingestion.",
                "Fragments were analyzed independently.",
                "Observed regions were separated from suspected anomalies.",
                "Unknown regions were preserved as unknown.",
                "No original reference evidence was assumed."
            ]
        }
    ],

    fragments: [
        {
            id: "F001",
            artifact: "Evidence File",
            type: "Observed Fragment",
            state: "observed",
            compatibility: 1,
            hashStatus: "Verified",
            reasoning:
                "Fragment is physically present and structurally consistent with the submitted evidence.",
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
            explanation:
                "Standalone evidence analysis completed."
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

    if (!hash) {
        return "—";
    }

    if (hash.length <= 18) {
        return hash;
    }

    return `${hash.slice(0, 10)}...${hash.slice(-6)}`;
}


function formatTimestamp(timestamp) {

    if (!timestamp) {
        return "—";
    }

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

    return Math.max(
        0,
        Math.min(100, number)
    );
}


function formatBytes(bytes) {

    if (
        !Number.isFinite(bytes) ||
        bytes <= 0
    ) {
        return "0 B";
    }

    const units = [
        "B",
        "KB",
        "MB",
        "GB"
    ];

    const index = Math.floor(
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
   BACKEND REQUEST
========================================================= */

async function analyzeEvidenceFile(file) {

    if (!file) {
        throw new Error(
            "No evidence file selected."
        );
    }

    const controller =
        new AbortController();

    const timeoutId =
        setTimeout(
            () => controller.abort(),
            API_CONFIG.timeout
        );

    try {

        const formData =
            new FormData();

        formData.append(
            "file",
            file
        );

        console.log(
            "Anvaya → uploading:",
            file.name
        );

        const response =
            await fetch(
                endpointUrl(
                    API_CONFIG.endpoints.analyze
                ),
                {
                    method: "POST",
                    body: formData,
                    signal: controller.signal
                }
            );

        if (!response.ok) {

            const errorText =
                await response.text();

            throw new Error(
                `Backend returned HTTP ${response.status}: ${errorText}`
            );
        }

        return await response.json();

    } catch (error) {

        if (
            error.name ===
            "AbortError"
        ) {

            throw new Error(
                "Analysis timed out after 120 seconds."
            );
        }

        throw error;

    } finally {

        clearTimeout(
            timeoutId
        );
    }
}


/* =========================================================
   RECOVERY REQUEST (NEW)
========================================================= */

async function recoverEvidenceFile(file) {

    if (!file) {
        throw new Error(
            "No evidence file selected."
        );
    }

    const controller =
        new AbortController();

    const timeoutId =
        setTimeout(
            () => controller.abort(),
            API_CONFIG.timeout
        );

    try {

        const formData =
            new FormData();

        formData.append(
            "file",
            file
        );

        console.log(
            "Anvaya → recovery:",
            file.name
        );

        const response =
            await fetch(
                endpointUrl(
                    API_CONFIG.endpoints.recover
                ),
                {
                    method: "POST",
                    body: formData,
                    signal: controller.signal
                }
            );

        if (!response.ok) {

            const errorText =
                await response.text();

            throw new Error(
                `Backend returned HTTP ${response.status}: ${errorText}`
            );
        }

        return await response.json();

    } catch (error) {

        if (
            error.name ===
            "AbortError"
        ) {

            throw new Error(
                "Recovery timed out after 120 seconds."
            );
        }

        throw error;

    } finally {

        clearTimeout(
            timeoutId
        );
    }
}


/* =========================================================
   RESPONSE NORMALIZATION
========================================================= */

function normalizeBackendResponse(response) {

    const caseData =
        response?.case || {};

    const evidence =
        response?.evidence || {};

    const fragmentAnalysis =
        response?.fragment_analysis || {};

    const formatValidation =
        response?.format_validation || {};

    const aiAnalysis =
        response?.ai_analysis || {};

    /*
     IMPORTANT:
     Do not declare evidenceIntegrity twice.
    */
    const integrityData =
        response?.evidence_integrity || {};

    const reconstruction =
        response?.reconstruction || {};

    const audit =
        response?.audit || {};

    const aiSummary =
        aiAnalysis.summary || {};

    const totalFragments =
        Number(
            fragmentAnalysis.total_fragments ||
            0
        );

    const anomalyFragments =
        Number(
            aiSummary.fragments_analyzed ||
            0
        );


    /* ---------------------------------------------------------
       STANDALONE EVIDENCE INTEGRITY
    --------------------------------------------------------- */

    const integrityValue =
        integrityData.evidence_integrity ??
        "N/A";

    const observedIntact =
        Number(
            integrityData.observed_intact ??
            0
        );

    const suspectedAnomalous =
        Number(
            integrityData.suspected_anomalous ??
            0
        );

    const unknownUnrecoverable =
        Number(
            integrityData.unknown_unrecoverable ??
            0
        );

    const observedPct =
        integrityData.observed_percentage ??
        "N/A";

    const suspectedPct =
        integrityData.suspected_percentage ??
        "N/A";

    const unknownPct =
        integrityData.unknown_percentage ??
        "N/A";


    /* ---------------------------------------------------------
       AI ANOMALY SUMMARY
    --------------------------------------------------------- */

    const normalFragments =
        Number(
            aiSummary.normal ??
            0
        );

    const suspiciousFragments =
        Number(
            aiSummary.suspicious ??
            0
        );

    const highAnomalyFragments =
        Number(
            aiSummary.high_anomaly ??
            0
        );


    /* ---------------------------------------------------------
       FORMAT VALIDATION
    --------------------------------------------------------- */

    const formatAnomalies =
        Array.isArray(
            formatValidation.anomalies
        )
            ? formatValidation.anomalies
            : [];

    const formatWarnings =
        Array.isArray(
            formatValidation.warnings
        )
            ? formatValidation.warnings
            : [];

    const formatValid =
        formatAnomalies.length === 0 &&
        formatWarnings.length === 0;


    /* ---------------------------------------------------------
       RECONSTRUCTION CANDIDATE
    --------------------------------------------------------- */

    const candidate =
        reconstruction.candidate ||
        {};

    const candidateObservedPct =
        candidate.observed_percentage ??
        "N/A";


    /* ---------------------------------------------------------
       EXPLAINABILITY
    --------------------------------------------------------- */

    const explainabilityItems = [

        `Evidence SHA-256: ${
            evidence.sha256 ||
            "Unavailable"
        }.`,


        `Total fragments analyzed: ${
            totalFragments
        }.`,


        `Format validation: ${
            formatValid
                ? "No structural anomalies detected."
                : `${formatAnomalies.length} anomaly(s), ${formatWarnings.length} warning(s).`
        }`,


        `Evidence integrity: ${
            integrityValue !== "N/A"
                ? integrityValue + "%"
                : "N/A"
        }.`,


        `Observed / Intact fragments: ${
            observedIntact
        } (${
            observedPct !== "N/A"
                ? observedPct + "%"
                : "N/A"
        }).`,


        `Suspected / Anomalous fragments: ${
            suspectedAnomalous
        } (${
            suspectedPct !== "N/A"
                ? suspectedPct + "%"
                : "N/A"
        }).`,


        `Unknown / Unrecoverable fragments: ${
            unknownUnrecoverable
        } (${
            unknownPct !== "N/A"
                ? unknownPct + "%"
                : "N/A"
        }).`,


        `AI anomaly analysis completed on ${
            anomalyFragments
        } fragments. Normal: ${
            normalFragments
        }, Suspicious: ${
            suspiciousFragments
        }, High anomaly: ${
            highAnomalyFragments
        }.`,


        candidate.observed_bytes !==
        undefined

            ? `Analysis candidate generated from ${
                candidate.observed_bytes
              } of ${
                candidate.total_bytes
              } observed bytes (${
                candidateObservedPct !== "N/A"
                    ? candidateObservedPct + "%"
                    : "N/A"
              }).`

            : "No reconstruction candidate was generated.",


        "Standalone analysis: no original reference evidence was supplied. Results describe the submitted evidence and do not establish recovery of missing historical data."
    ];


    /* ---------------------------------------------------------
       RETURN NORMALIZED OBJECT
    --------------------------------------------------------- */

    return {

        caseInfo: {

            id:
                caseData.case_id ||
                "UNKNOWN",

            evidenceId:
                evidence.filename ||
                "UNKNOWN",

            sha256:
                evidence.sha256 ||
                "",

            inputTimestamp:
                caseData.created_at ||
                "",

            processingTimestamp:
                audit.created_at ||
                caseData.created_at ||
                "",

            operationCount:
                Number(
                    audit.event_count ||
                    0
                ),

            originalHash:
                evidence.sha256 ||
                "",

            recoveredArtifactHash:
                candidate.sha256 ||
                "",

            provenanceStatus:
                audit.status ===
                "audit_log_created"

                    ? "Tamper-evident audit recorded"

                    : "Audit unavailable"
        },


        stats: {

            fileCount: 1,

            evidenceIntegrity:
                integrityValue === "N/A"
                    ? "N/A"
                    : Math.round(
                        Number(
                            integrityValue
                        )
                    ),

            observedIntact:
                observedIntact,

            suspectedAnomalous:
                suspectedAnomalous,

            unknownUnrecoverable:
                unknownUnrecoverable,

            anomalyScore:
                (
                    suspiciousFragments +
                    highAnomalyFragments
                ) > 0
                    ? "Elevated"
                    : "Normal",

            totalFragments:
                totalFragments,

            formatValid:
                formatValid,

            /*
             This is deliberately N/A.
             Anvaya is not claiming statistical confidence.
            */
            confidence:
                "N/A"
        },


        artifacts: [

            {

                name:
                    evidence.filename ||
                    "Evidence File",

                type:
                    evidence.file_type ||
                    "Unknown",

                evidenceIntegrity:
                    integrityValue === "N/A"
                        ? "N/A"
                        : Math.round(
                            Number(
                                integrityValue
                            )
                        ),

                observedIntact:
                    observedIntact,

                suspectedAnomalous:
                    suspectedAnomalous,

                unknownUnrecoverable:
                    unknownUnrecoverable,

                state:
                    formatValid
                        ? "observed"
                        : "suspected",

                explanation:
                    "Anvaya analyzed the submitted evidence using fragment integrity, format validation, anomaly analysis and reconstruction mapping. No original reference evidence was supplied.",

                explainability:
                    explainabilityItems
            }
        ],


        fragments:
            buildFrontendFragments(
                reconstruction.map ||
                [],
                evidence.filename ||
                "Evidence File"
            ),


        timeline:
            buildTimeline(
                response
            ),


        audit: {

            caseId:
                caseData.case_id ||
                "",

            evidenceId:
                evidence.filename ||
                "",

            sha256:
                evidence.sha256 ||
                "",

            inputTimestamp:
                caseData.created_at ||
                "",

            processingTimestamp:
                audit.created_at ||
                caseData.created_at ||
                "",

            operationCount:
                Number(
                    audit.event_count ||
                    0
                ),

            originalHash:
                evidence.sha256 ||
                "",

            recoveredHash:
                candidate.sha256 ||
                "",

            provenanceStatus:
                audit.status ===
                "audit_log_created"

                    ? "Tamper-evident audit recorded"

                    : "Unknown"
        },


        raw:
            response
    };
}


/* =========================================================
   NORMALIZE RECOVERY RESPONSE
========================================================= */

function normalizeRecoveryResponse(response) {

    const caseData = response?.case || {};
    const evidence = response?.evidence || {};
    const fragmentClassification = response?.fragment_classification || {};
    const formatValidation = response?.format_validation || {};
    const recovery = response?.recovery || {};
    const report = response?.report || {};
    const audit = response?.audit || {};

    const recoveryEvidenceSummary = recovery?.evidence_summary || {};
    const recoveryMetrics = recovery?.recovery_metrics || {};
    const validation = recovery?.validation || {};

    const statusDist = recoveryEvidenceSummary.status_distribution || {};
    const strategyDist = recoveryEvidenceSummary.strategy_distribution || {};

    const recoveredBytes = recoveryMetrics.recovered_bytes || 0;
    const repairedBytes = recoveryMetrics.repaired_bytes || 0;
    const inferredBytes = recoveryMetrics.inferred_bytes || 0;
    const unknownBytes = recoveryMetrics.unknown_bytes || 0;

    const totalFragments = Number(fragmentClassification.total || 0);
    const intactFragments = Number(fragmentClassification.intact || 0);
    const corruptedFragments = Number(fragmentClassification.corrupted || 0);
    const missingFragments = Number(fragmentClassification.missing || 0);
    const duplicateFragments = Number(fragmentClassification.duplicate || 0);

    const formatAnomalies = Array.isArray(formatValidation.anomalies) ? formatValidation.anomalies : [];
    const formatWarnings = Array.isArray(formatValidation.warnings) ? formatValidation.warnings : [];
    const formatValid = formatAnomalies.length === 0 && formatWarnings.length === 0;

    /* ---------------------------------------------------------
       EXPLAINABILITY
    --------------------------------------------------------- */

    const explainabilityItems = [

        `Evidence SHA-256: ${evidence.sha256 || "Unavailable"}.`,

        `Total fragments: ${totalFragments}.`,

        `Fragment classification: ${intactFragments} INTACT, ${corruptedFragments} CORRUPTED, ${missingFragments} MISSING, ${duplicateFragments} DUPLICATE.`,

        `Format validation: ${formatValid ? "No structural anomalies detected." : `${formatAnomalies.length} anomaly(s), ${formatWarnings.length} warning(s).`}`,

        `Recovery evidence: ${recoveredBytes} bytes RECOVERED, ${repairedBytes} bytes REPAIRED, ${inferredBytes} bytes AI-INFERRED, ${unknownBytes} bytes UNKNOWN.`,

        `Recovery strategies: ${Object.keys(strategyDist).join(", ") || "None"}.`,

        `Average confidence: ${recoveryEvidenceSummary.average_confidence || "N/A"}.`,

        `Validation: ${validation.format || "Unknown"} - ${validation.valid_header || validation.utf8_valid ? "Valid" : "Issues detected"}.`,

        "Recovery pipeline: Ingestion → Identification → Fragmentation → Classification → Reconstruction → File-Type Recovery → Evidence Classification → Validation → Report."
    ];


    /* ---------------------------------------------------------
       RETURN NORMALIZED OBJECT
    --------------------------------------------------------- */

    return {

        caseInfo: {

            id: caseData.case_id || "UNKNOWN",

            evidenceId: evidence.filename || "UNKNOWN",

            sha256: evidence.sha256 || "",

            inputTimestamp: caseData.created_at || "",

            processingTimestamp: audit.created_at || caseData.created_at || "",

            operationCount: Number(audit.event_count || 0),

            originalHash: evidence.sha256 || "",

            recoveredArtifactHash: recovery.recovered_file?.sha256 || "",

            provenanceStatus: audit.status === "audit_log_created" ? "Tamper-evident audit recorded" : "Audit unavailable"
        },


        stats: {

            fileCount: 1,

            evidenceIntegrity: recoveryMetrics.non_zero_percentage || "N/A",

            observedIntact: intactFragments,

            suspectedAnomalous: corruptedFragments,

            unknownUnrecoverable: missingFragments,

            anomalyScore: (corruptedFragments + missingFragments) > 0 ? "Elevated" : "Normal",

            totalFragments: totalFragments,

            formatValid: formatValid,

            confidence: recoveryEvidenceSummary.average_confidence || "N/A"
        },


        artifacts: [

            {

                name: evidence.filename || "Evidence File",

                type: evidence.file_type || "Unknown",

                evidenceIntegrity: recoveryMetrics.non_zero_percentage || "N/A",

                observedIntact: intactFragments,

                suspectedAnomalous: corruptedFragments,

                unknownUnrecoverable: missingFragments,

                state: formatValid ? "recovered" : "repaired",

                explanation: "Anvaya recovered the evidence using fragment classification, structural repair, and content inference strategies.",

                explainability: explainabilityItems,

                recovery: {
                    recoveredBytes: recoveredBytes,
                    repairedBytes: repairedBytes,
                    inferredBytes: inferredBytes,
                    unknownBytes: unknownBytes,
                    strategies: strategyDist
                }
            }
        ],


        fragments: buildRecoveryFragments(
            fragmentClassification,
            recoveryEvidenceSummary,
            evidence.filename || "Evidence File"
        ),


        timeline: buildRecoveryTimeline(response),


        audit: {

            caseId: caseData.case_id || "",

            evidenceId: evidence.filename || "",

            sha256: evidence.sha256 || "",

            inputTimestamp: caseData.created_at || "",

            processingTimestamp: audit.created_at || caseData.created_at || "",

            operationCount: Number(audit.event_count || 0),

            originalHash: evidence.sha256 || "",

            recoveredHash: recovery.recovered_file?.sha256 || "",

            provenanceStatus: audit.status === "audit_log_created" ? "Tamper-evident audit recorded" : "Unknown"
        },


        raw: response
    };
}


/* =========================================================
   BUILD RECOVERY FRAGMENTS
========================================================= */

function buildRecoveryFragments(fragmentClassification, evidenceSummary, artifactName) {
    const fragments = [];
    const total = Number(fragmentClassification.total || 0);
    
    if (total === 0) return fragments;

    // Create fragment entries based on classification
    const classes = [
        { key: 'intact', label: 'INTACT', state: 'observed', count: fragmentClassification.intact || 0 },
        { key: 'corrupted', label: 'CORRUPTED', state: 'suspected', count: fragmentClassification.corrupted || 0 },
        { key: 'missing', label: 'MISSING', state: 'unknown', count: fragmentClassification.missing || 0 },
        { key: 'duplicate', label: 'DUPLICATE', state: 'recovered', count: fragmentClassification.duplicate || 0 }
    ];

    let index = 0;
    for (const cls of classes) {
        for (let i = 0; i < cls.count; i++) {
            fragments.push({
                id: `F${String(++index).padStart(3, '0')}`,
                artifact: artifactName,
                type: cls.label + " Fragment",
                state: cls.state,
                compatibility: cls.state === 'observed' ? 1 : cls.state === 'recovered' ? 0.8 : cls.state === 'suspected' ? 0.5 : 0.1,
                hashStatus: cls.state === 'observed' ? "Verified" : cls.state === 'recovered' ? "Recovered" : cls.state === 'suspected' ? "Anomalous" : "Unknown",
                reasoning: cls.state === 'observed' 
                    ? "Fragment is physically present and structurally consistent with the submitted evidence."
                    : cls.state === 'recovered'
                    ? "Fragment recovered via exact duplicate match."
                    : cls.state === 'suspected'
                    ? "Fragment shows anomalies; content reconstructed via structural repair or inference."
                    : "Fragment missing or unrecoverable; zero-filled in recovery.",
                connections: [],
                x: 90 + (index % 10) * 120,
                y: 150 + Math.floor(index / 10) * 120
            });
        }
    }

    return fragments;
}


/* =========================================================
   BUILD RECOVERY TIMELINE
========================================================= */

function buildRecoveryTimeline(response) {
    const caseData = response?.case || {};
    const audit = response?.audit || {};
    const timeline = [];

    if (caseData.created_at) {
        timeline.push({
            timestamp: caseData.created_at,
            event: "Case Created",
            description: "New digital evidence case initialized."
        });
    }

    // Add audit events
    if (Array.isArray(audit.events)) {
        for (const event of audit.events) {
            timeline.push({
                timestamp: event.timestamp,
                event: event.event,
                description: event.description
            });
        }
    }

    return timeline;
}


/* =========================================================
   BUILD FRONTEND FRAGMENTS (EXISTING)
========================================================= */

function buildFrontendFragments(
    reconstructionMap,
    artifactName
) {

    if (
        !Array.isArray(
            reconstructionMap
        )
    ) {

        return [];
    }


    const fragments =
        reconstructionMap.map(
            (item, index) => {

                let stateValue =
                    "unknown";

                let hashStatus =
                    "Unknown";

                let reasoning =
                    "No additional fragment reasoning was supplied.";


                /* -------------------------------------------------
                   NEW STANDALONE STATES
                ------------------------------------------------- */

                if (
                    item.status ===
                        "OBSERVED" ||

                    item.status ===
                        "OBSERVED / INTACT"
                ) {

                    stateValue =
                        "observed";

                    hashStatus =
                        "Verified";

                    reasoning =
                        "Fragment is physically present and structurally consistent with expectations.";
                }

                else if (
                    item.status ===
                        "SUSPECTED" ||

                    item.status ===
                        "SUSPECTED / ANOMALOUS"
                ) {

                    stateValue =
                        "suspected";

                    hashStatus =
                        "Anomalous";

                    reasoning =
                        "Fragment shows structural anomalies or inconsistencies. Original content cannot be determined from this evidence alone.";
                }

                else if (
                    item.status ===
                        "UNKNOWN" ||

                    item.status ===
                        "UNKNOWN / UNRECOVERABLE"
                ) {

                    stateValue =
                        "unknown";

                    hashStatus =
                        "Indeterminate";

                    reasoning =
                        "No discernible structure or content in this region. Cannot determine if data was originally present.";
                }


                /* -------------------------------------------------
                   LEGACY BACKEND STATES
                ------------------------------------------------- */

                else if (
                    item.status ===
                    "RECOVERED"
                ) {

                    stateValue =
                        "observed";

                    hashStatus =
                        "Verified";

                    reasoning =
                        "Fragment is physically present and structurally consistent with expectations.";
                }

                else if (
                    item.status ===
                    "CORRUPTED"
                ) {

                    stateValue =
                        "suspected";

                    hashStatus =
                        "Anomalous";

                    reasoning =
                        `${
                            item.changed_bytes ||
                            0
                        } changed byte(s) were detected in this fragment. Original content cannot be determined from this evidence alone.`;
                }

                else if (
                    item.status ===
                    "MISSING"
                ) {

                    stateValue =
                        "unknown";

                    hashStatus =
                        "Missing";

                    reasoning =
                        "No surviving physical fragment was matched to this position.";
                }


                /* -------------------------------------------------
                   DISPLAY TYPE
                ------------------------------------------------- */

                let typeValue =
                    "Unknown Fragment";

                if (
                    stateValue ===
                    "observed"
                ) {

                    typeValue =
                        "Observed Fragment";
                }

                else if (
                    stateValue ===
                    "suspected"
                ) {

                    typeValue =
                        "Suspected Fragment";
                }


                /* -------------------------------------------------
                   COMPATIBILITY
                ------------------------------------------------- */

                let compatibility =
                    0;

                if (
                    stateValue ===
                    "observed"
                ) {

                    compatibility =
                        1;
                }

                else if (
                    stateValue ===
                    "suspected"
                ) {

                    compatibility =
                        0.5;
                }


                return {

                    id:
                        `F${String(
                            index + 1
                        ).padStart(
                            3,
                            "0"
                        )}`,

                    artifact:
                        artifactName,

                    type:
                        typeValue,

                    state:
                        stateValue,

                    compatibility:
                        compatibility,

                    hashStatus:
                        hashStatus,

                    reasoning:
                        reasoning,

                    connections: [],

                    originalIndex:
                        item.original_index,

                    filename:
                        item.filename,

                    sha256:
                        item.sha256,

                    size:
                        item.size,

                    changedBytes:
                        item.changed_bytes ||
                        0,

                    x: 0,

                    y: 0
                };
            }
        );


    /* ---------------------------------------------------------
       GRAPH LAYOUT
    --------------------------------------------------------- */

    const fragmentCount =
        fragments.length;

    let cols;
    let spacingX;
    let spacingY;


    if (
        fragmentCount <= 12
    ) {

        cols =
            Math.min(
                4,
                fragmentCount
            );

        spacingX =
            120;

        spacingY =
            90;
    }

    else if (
        fragmentCount <= 30
    ) {

        cols =
            5;

        spacingX =
            110;

        spacingY =
            80;
    }

    else if (
        fragmentCount <= 60
    ) {

        cols =
            6;

        spacingX =
            100;

        spacingY =
            75;
    }

    else {

        cols =
            7;

        spacingX =
            95;

        spacingY =
            70;
    }


    const startX =
        50;

    const startY =
        50;


    fragments.forEach(
        (fragment, index) => {

            const col =
                index % cols;

            const row =
                Math.floor(
                    index / cols
                );

            fragment.x =
                startX +
                col *
                spacingX;

            fragment.y =
                startY +
                row *
                spacingY;
        }
    );


    /*
     Connections represent reconstruction order only.
     They are NOT AI-inferred relationships.
    */

    fragments.forEach(
        (fragment, index) => {

            if (
                index <
                fragments.length - 1
            ) {

                fragment.connections =
                    [
                        fragments[
                            index + 1
                        ].id
                    ];
            }
        }
    );


    return fragments;
}


/* =========================================================
   BUILD TIMELINE
========================================================= */

function buildTimeline(
    response
) {

    const caseData =
        response?.case ||
        {};

    const evidence =
        response?.evidence ||
        {};

    const fragmentAnalysis =
        response?.fragment_analysis ||
        {};

    const integrity =
        response?.integrity ||
        {};

    const corruption =
        response?.corruption ||
        {};

    const ai =
        response?.ai_analysis ||
        {};

    const reconstruction =
        response?.reconstruction ||
        {};

    const audit =
        response?.audit ||
        {};

    const events = [];


    events.push({

        time:
            formatTimestamp(
                caseData.created_at
            ),

        operation:
            "Case created",

        status:
            "success",

        explanation:
            `Created case ${
                caseData.case_id ||
                "unknown"
            }.`
    });


    events.push({

        time:
            formatTimestamp(
                caseData.created_at
            ),

        operation:
            "Evidence ingestion",

        status:
            "success",

        explanation:
            `Evidence ${
                evidence.filename ||
                "file"
            } was ingested and hashed.`
    });


    events.push({

        time:
            formatTimestamp(
                caseData.created_at
            ),

        operation:
            "Fragment analysis",

        status:
            "success",

        explanation:
            `${
                fragmentAnalysis.total_fragments ||
                0
            } fragments were analyzed.`
    });


    if (integrity) {

        events.push({

            time:
                formatTimestamp(
                    caseData.created_at
                ),

            operation:
                "Integrity analysis",

            status:
                "success",

            explanation:
                "Fragment integrity and duplicate analysis completed."
        });
    }


    if (
        corruption?.summary
    ) {

        events.push({

            time:
                formatTimestamp(
                    caseData.created_at
                ),

            operation:
                "Corruption analysis",

            status:
                Number(
                    corruption.summary
                        .corrupted_fragments ||
                    0
                ) > 0

                    ? "warning"

                    : "success",

            explanation:
                `${
                    corruption.summary
                        .corrupted_fragments ||
                    0
                } corrupted and ${
                    corruption.summary
                        .missing_fragments ||
                    0
                } missing fragment(s) detected.`
        });
    }


    if (
        ai?.summary
    ) {

        events.push({

            time:
                formatTimestamp(
                    caseData.created_at
                ),

            operation:
                "AI anomaly analysis",

            status:
                "success",

            explanation:
                `Explainable heuristic analysis completed on ${
                    ai.summary
                        .fragments_analyzed ||
                    0
                } fragments.`
        });
    }


    if (
        reconstruction?.candidate
    ) {

        events.push({

            time:
                formatTimestamp(
                    caseData.created_at
                ),

            operation:
                "Reconstruction candidate generated",

            status:
                "warning",

            explanation:
                "A reconstruction candidate was generated only from surviving evidence."
        });
    }


    if (
        audit?.event_count
    ) {

        events.push({

            time:
                formatTimestamp(
                    caseData.created_at
                ),

            operation:
                "Audit log created",

            status:
                "success",

            explanation:
                `${
                    audit.event_count
                } audit event(s) were recorded.`
        });
    }


    return events;
}


/* =========================================================
   MODE INDICATOR
========================================================= */

function renderModeIndicator() {

    const indicator =
        document.getElementById(
            "modeIndicator"
        );

    const label =
        document.getElementById(
            "modeLabel"
        );

    const note =
        document.getElementById(
            "connectionNote"
        );

    const dataSourceNote =
        document.getElementById(
            "dataSourceNote"
        );


    if (
        !indicator ||
        !label
    ) {
        return;
    }


    indicator.dataset.mode =
        state.mode;


    if (
        state.mode ===
        "live"
    ) {

        label.textContent =
            "LIVE BACKEND";

        if (note) {

            note.textContent =
                "Connected to the FastAPI forensic engine.";
        }

        if (
            dataSourceNote
        ) {

            dataSourceNote.textContent =
                "Live API data";
        }

    }

    else if (
        state.mode ===
        "demo"
    ) {

        label.textContent =
            "DEMO MODE";

        if (note) {

            note.textContent =
                "Backend unavailable - using demonstration dataset.";
        }

        if (
            dataSourceNote
        ) {

            dataSourceNote.textContent =
                "Mock / demo data";
        }

    }

    else {

        label.textContent =
            "ANALYSIS ERROR";

        if (note) {

            note.textContent =
                "The forensic backend returned an error.";
        }

        if (
            dataSourceNote
        ) {

            dataSourceNote.textContent =
                "Backend error";
        }
    }
}


/* =========================================================
   CASE META
========================================================= */

function renderCaseMeta(
    caseInfo,
    audit
) {

    caseInfo =
        caseInfo ||
        {};

    audit =
        audit ||
        {};


    const label =
        document.getElementById(
            "caseIdLabel"
        );


    if (label) {

        label.textContent =
            caseInfo.id ||
            "UNKNOWN";
    }


    const auditCase =
        document.getElementById(
            "auditCaseId"
        );

    const evidenceId =
        document.getElementById(
            "auditEvidenceId"
        );

    const auditHash =
        document.getElementById(
            "auditHash"
        );

    const inputTime =
        document.getElementById(
            "auditInputTime"
        );

    const processTime =
        document.getElementById(
            "auditProcessTime"
        );

    const opCount =
        document.getElementById(
            "auditOps"
        );

    const originalHash =
        document.getElementById(
            "auditOriginalHash"
        );

    const recoveredHash =
        document.getElementById(
            "auditRecoveredHash"
        );

    const provenance =
        document.getElementById(
            "auditProvenance"
        );


    if (auditCase) {

        auditCase.textContent =
            audit.caseId ||
            caseInfo.id ||
            "—";
    }


    if (evidenceId) {

        evidenceId.textContent =
            audit.evidenceId ||
            caseInfo.evidenceId ||
            "—";
    }


    if (auditHash) {

        auditHash.textContent =
            shortenHash(
                audit.sha256 ||
                caseInfo.sha256
            );
    }


    if (inputTime) {

        inputTime.textContent =
            formatTimestamp(
                audit.inputTimestamp ||
                caseInfo.inputTimestamp
            );
    }


    if (processTime) {

        processTime.textContent =
            formatTimestamp(
                audit.processingTimestamp ||
                caseInfo.processingTimestamp
            );
    }


    if (opCount) {

        opCount.textContent =
            audit.operationCount ||
            caseInfo.operationCount ||
            0;
    }


    if (originalHash) {

        originalHash.textContent =
            shortenHash(
                audit.originalHash ||
                caseInfo.originalHash
            );
    }


    if (recoveredHash) {

        recoveredHash.textContent =
            shortenHash(
                audit.recoveredHash ||
                caseInfo.recoveredArtifactHash
            );
    }


    if (provenance) {

        provenance.textContent =
            audit.provenanceStatus ||
            caseInfo.provenanceStatus ||
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

function renderStats(
    stats
) {

    stats =
        stats ||
        {};


    const fileCount =
        document.getElementById(
            "fileCount"
        );

    const evidenceIntegrityCount =
        document.getElementById(
            "recoveredCount"
        );

    const confidence =
        document.getElementById(
            "confidence"
        );

    const fragmentCount =
        document.getElementById(
            "fragmentCount"
        );


    if (fileCount) {

        fileCount.textContent =
            Number(
                stats.fileCount ||
                0
            ).toLocaleString();
    }


    /*
     The existing HTML uses recoveredCount
     for the main integrity value.
    */

    if (
        evidenceIntegrityCount
    ) {

        if (
            stats.evidenceIntegrity ===
            "N/A" ||
            stats.evidenceIntegrity ===
            undefined
        ) {

            evidenceIntegrityCount.textContent =
                "N/A";

        } else {

            evidenceIntegrityCount.textContent =
                `${percentage(
                    stats.evidenceIntegrity
                )}%`;
        }
    }


    /*
     AI confidence deliberately remains N/A.
     Anvaya currently performs explainable
     heuristic analysis, not statistical
     confidence estimation.
    */

    if (confidence) {

        confidence.textContent =
            "N/A";
    }


    if (fragmentCount) {

        fragmentCount.textContent =
            Number(
                stats.totalFragments ||
                0
            ).toLocaleString();
    }


    const recoveredMetric =
        document.getElementById(
            "recoveredMetric"
        );

    const inferredMetric =
        document.getElementById(
            "inferredMetric"
        );

    const missingMetric =
        document.getElementById(
            "missingMetric"
        );


    const recoveredMetricBar =
        document.getElementById(
            "recoveredMetricBar"
        );

    const inferredMetricBar =
        document.getElementById(
            "inferredMetricBar"
        );

    const missingMetricBar =
        document.getElementById(
            "missingMetricBar"
        );


    const observed =
        stats.observedIntact ??
        stats.evidenceIntegrity ??
        0;

    const suspected =
        stats.suspectedAnomalous ??
        0;

    const unknown =
        stats.unknownUnrecoverable ??
        0;


    if (recoveredMetric) {

        recoveredMetric.textContent =
            observed === "N/A"
                ? "N/A"
                : `${percentage(
                    observed
                )}%`;
    }


    if (inferredMetric) {

        inferredMetric.textContent =
            `${percentage(
                suspected
            )}%`;
    }


    if (missingMetric) {

        missingMetric.textContent =
            `${percentage(
                unknown
            )}%`;
    }


    if (recoveredMetricBar) {

        recoveredMetricBar.style.width =
            observed === "N/A"
                ? "0%"
                : `${percentage(
                    observed
                )}%`;
    }


    if (inferredMetricBar) {

        inferredMetricBar.style.width =
            `${percentage(
                suspected
            )}%`;
    }


    if (missingMetricBar) {

        missingMetricBar.style.width =
            `${percentage(
                unknown
            )}%`;
    }
}


/* =========================================================
   ARTIFACT TABLE
========================================================= */

function renderArtifactTable(
    artifacts
) {

    const tableBody =
        document.getElementById(
            "artifactTableBody"
        );


    if (!tableBody) {
        return;
    }


    if (
        !Array.isArray(
            artifacts
        ) ||
        artifacts.length === 0
    ) {

        tableBody.innerHTML = `
            <div class="artifact-empty">
                No evidence artifacts analyzed yet.
            </div>
        `;

        return;
    }


    tableBody.innerHTML =
        artifacts
            .map(
                (artifact) => {

                    const stateClass =
                        artifact.state ===
                        "observed"

                            ? "recovered"

                            : artifact.state ===
                              "suspected"

                                ? "partial"

                                : "missing";


                    const integrityValue =
                        artifact.evidenceIntegrity ??
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
                                ${escapeHtml(
                                    artifact.name
                                )}
                            </span>

                            <span class="artifact-type">
                                ${escapeHtml(
                                    artifact.type
                                )}
                            </span>

                            <span class="artifact-recovery">
                                ${
                                    integrityValue ===
                                    "N/A"
                                        ? "N/A"
                                        : `${integrityValue}%`
                                }
                            </span>

                            <span class="badge ${stateClass}">
                                ${escapeHtml(
                                    artifact.state
                                )}
                            </span>

                        </div>
                    `;
                }
            )
            .join("");


    tableBody
        .querySelectorAll(
            ".artifact-row"
        )
        .forEach(
            (row) => {

                row.addEventListener(
                    "click",
                    () => {

                        const name =
                            row.dataset
                                .artifactName;


                        const artifact =
                            artifacts.find(
                                (item) =>
                                    item.name ===
                                    name
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
            }
        );
}


/* =========================================================
   TIMELINE
========================================================= */

function renderTimeline(
    events
) {

    const timelineList =
        document.getElementById(
            "timelineList"
        );


    if (!timelineList) {
        return;
    }


    if (
        !Array.isArray(events) ||
        events.length === 0
    ) {

        timelineList.innerHTML = `
            <div class="timeline-empty">
                No timeline events available.
            </div>
        `;

        return;
    }


    timelineList.innerHTML =
        events
            .map(
                (event) => {

                    const statusClass =
                        {
                            success:
                                "success",

                            warning:
                                "warning",

                            muted:
                                "muted"
                        }[
                            event.status
                        ] ||
                        "muted";


                    return `
                        <div class="timeline-event">

                            <div class="timeline-time">
                                ${escapeHtml(
                                    event.time
                                )}
                            </div>

                            <div class="timeline-copy">

                                <strong>
                                    ${escapeHtml(
                                        event.operation
                                    )}
                                </strong>

                                <span>
                                    ${escapeHtml(
                                        event.explanation
                                    )}
                                </span>

                            </div>

                            <div class="timeline-status ${statusClass}">
                                ${escapeHtml(
                                    event.status
                                )}
                            </div>

                        </div>
                    `;
                }
            )
            .join("");
}


/* =========================================================
   FRAGMENT GRAPH
========================================================= */

function renderFragmentGraph(
    fragments
) {

    const svg =
        document.getElementById(
            "fragmentGraph"
        );


    if (!svg) {
        return;
    }


    svg.innerHTML = "";


    if (
        !Array.isArray(fragments) ||
        fragments.length === 0
    ) {

        svg.setAttribute(
            "viewBox",
            "0 0 700 300"
        );

        return;
    }


    const stateColors = {

        observed:
            "#35d07f",

        suspected:
            "#f4c95d",

        unknown:
            "#ef6262",

        recovered:
            "#35d07f",

        inferred:
            "#f4c95d",

        missing:
            "#ef6262"
    };


    const stateDash = {

        observed:
            "0",

        suspected:
            "7 8",

        unknown:
            "2 6",

        recovered:
            "0",

        inferred:
            "7 8",

        missing:
            "2 6"
    };


    const nodeMap =
        new Map();


    fragments.forEach(
        (fragment) => {

            nodeMap.set(
                fragment.id,
                fragment
            );
        }
    );


    /*
     * Calculate dynamic graph bounds.
    */

    let minX =
        Infinity;

    let minY =
        Infinity;

    let maxX =
        -Infinity;

    let maxY =
        -Infinity;


    fragments.forEach(
        (fragment) => {

            minX =
                Math.min(
                    minX,
                    fragment.x
                );

            minY =
                Math.min(
                    minY,
                    fragment.y
                );

            maxX =
                Math.max(
                    maxX,
                    fragment.x
                );

            maxY =
                Math.max(
                    maxY,
                    fragment.y
                );
        }
    );


    const padding =
        70;


    const viewBoxWidth =
        Math.max(
            500,
            maxX -
            minX +
            padding * 2
        );


    const viewBoxHeight =
        Math.max(
            300,
            maxY -
            minY +
            padding * 2
        );


    svg.setAttribute(
        "viewBox",
        `${-minX + padding} ${-minY + padding} ${viewBoxWidth} ${viewBoxHeight}`
    );


    const ns =
        "http://www.w3.org/2000/svg";


    /* ---------------------------------------------------------
       CONNECTIONS
    --------------------------------------------------------- */

    fragments.forEach(
        (fragment) => {

            (
                fragment.connections ||
                []
            ).forEach(
                (targetId) => {

                    const target =
                        nodeMap.get(
                            targetId
                        );


                    if (!target) {
                        return;
                    }


                    const line =
                        document.createElementNS(
                            ns,
                            "line"
                        );


                    const strokeColor =
                        stateColors[
                            fragment.state
                        ] ||
                        stateColors.unknown;


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
                        stateDash.unknown
                    );

                    line.setAttribute(
                        "stroke-linecap",
                        "round"
                    );

                    line.setAttribute(
                        "opacity",
                        "0.8"
                    );


                    svg.appendChild(
                        line
                    );
                }
            );
        }
    );


    /* ---------------------------------------------------------
       NODES
    --------------------------------------------------------- */

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
                stateColors.unknown;


            circle.setAttribute(
                "fill",
                color
            );


            circle.setAttribute(
                "fill-opacity",
                fragment.state ===
                "unknown"
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


            group.appendChild(
                circle
            );

            group.appendChild(
                text
            );


            svg.appendChild(
                group
            );


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
                        event.key ===
                            "Enter" ||

                        event.key ===
                            " "
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
                item.id ===
                fragmentId
        );


    if (!fragment) {
        return;
    }


    state.selectedFragment =
        fragment;


    const idElement =
        document.getElementById(
            "selectedFragmentId"
        );

    const stateElement =
        document.getElementById(
            "selectedFragmentState"
        );

    const typeElement =
        document.getElementById(
            "selectedFragmentType"
        );

    const hashElement =
        document.getElementById(
            "selectedFragmentHash"
        );

    const reasoningElement =
        document.getElementById(
            "selectedFragmentReasoning"
        );

    const sizeElement =
        document.getElementById(
            "selectedFragmentSize"
        );


    if (idElement) {

        idElement.textContent =
            fragment.id ||
            "—";
    }


    if (stateElement) {

        stateElement.textContent =
            getReadableFragmentState(
                fragment.state
            );

        stateElement.className =
            `fragment-state ${fragment.state}`;
    }


    if (typeElement) {

        typeElement.textContent =
            fragment.type ||
            "—";
    }


    if (hashElement) {

        hashElement.textContent =
            shortenHash(
                fragment.sha256
            );
    }


    if (reasoningElement) {

        reasoningElement.textContent =
            fragment.reasoning ||
            "No reasoning available.";
    }


    if (sizeElement) {

        sizeElement.textContent =
            fragment.size !==
            undefined

                ? formatBytes(
                    Number(
                        fragment.size
                    )
                )

                : "—";
    }


    /*
     Optional legacy IDs.
    */

    const legacyFragmentId =
        document.getElementById(
            "fragmentId"
        );

    if (legacyFragmentId) {

        legacyFragmentId.textContent =
            fragment.id;
    }


    const legacyFragmentStatus =
        document.getElementById(
            "fragmentStatus"
        );

    if (legacyFragmentStatus) {

        legacyFragmentStatus.textContent =
            getReadableFragmentState(
                fragment.state
            );
    }


    const legacyFragmentReason =
        document.getElementById(
            "fragmentReason"
        );

    if (legacyFragmentReason) {

        legacyFragmentReason.textContent =
            fragment.reasoning;
    }


    /*
     If a modal exists, open it.
    */

    const modal =
        document.getElementById(
            "fragmentModal"
        );


    if (modal) {

        openFragmentModal(
            fragment
        );
    }
}


/* =========================================================
   READABLE STATUS
========================================================= */

function getReadableFragmentState(
    value
) {

    switch (
        String(
            value ||
            ""
        ).toLowerCase()
    ) {

        case "observed":
        case "recovered":

            return "Observed / Intact";


        case "suspected":
        case "inferred":

            return "Suspected / Anomalous";


        case "unknown":
        case "missing":

            return "Unknown / Unrecoverable";


        default:

            return "Unknown";
    }
}


/* =========================================================
   FRAGMENT MODAL
========================================================= */

function openFragmentModal(
    fragment
) {

    state.selectedFragment =
        fragment;


    const modal =
        document.getElementById(
            "fragmentModal"
        );


    if (!modal) {
        return;
    }


    const title =
        modal.querySelector(
            "[data-fragment-title]"
        );


    const body =
        modal.querySelector(
            "[data-fragment-body]"
        );


    if (title) {

        title.textContent =
            fragment.id ||
            "Fragment";
    }


    if (body) {

        body.innerHTML = `

            <div class="modal-detail-grid">

                <div>
                    <span>State</span>
                    <strong>
                        ${escapeHtml(
                            getReadableFragmentState(
                                fragment.state
                            )
                        )}
                    </strong>
                </div>

                <div>
                    <span>Type</span>
                    <strong>
                        ${escapeHtml(
                            fragment.type ||
                            "Unknown"
                        )}
                    </strong>
                </div>

                <div>
                    <span>Hash status</span>
                    <strong>
                        ${escapeHtml(
                            fragment.hashStatus ||
                            "Unknown"
                        )}
                    </strong>
                </div>

                <div>
                    <span>Size</span>
                    <strong>
                        ${
                            fragment.size !==
                            undefined

                                ? escapeHtml(
                                    formatBytes(
                                        Number(
                                            fragment.size
                                        )
                                    )
                                )

                                : "—"
                        }
                    </strong>
                </div>

            </div>

            <div class="modal-explanation">

                <h4>
                    Why Anvaya classified it this way
                </h4>

                <p>
                    ${escapeHtml(
                        fragment.reasoning ||
                        "No explanation available."
                    )}
                </p>

            </div>

        `;
    }


    modal.hidden =
        false;

    modal.classList.add(
        "open"
    );
}


/* =========================================================
   ARTIFACT MODAL
========================================================= */

function openArtifactModal(
    artifact
) {

    const modal =
        document.getElementById(
            "artifactModal"
        );


    if (!modal) {
        return;
    }


    const title =
        modal.querySelector(
            "[data-artifact-title]"
        );


    const body =
        modal.querySelector(
            "[data-artifact-body]"
        );


    if (title) {

        title.textContent =
            artifact.name ||
            "Evidence Artifact";
    }


    if (body) {

        const explanations =
            Array.isArray(
                artifact.explainability
            )
                ? artifact.explainability
                : [];


        body.innerHTML = `

            <div class="modal-detail-grid">

                <div>
                    <span>Format</span>
                    <strong>
                        ${escapeHtml(
                            artifact.type ||
                            "Unknown"
                        )}
                    </strong>
                </div>

                <div>
                    <span>Evidence Integrity</span>
                    <strong>
                        ${
                            artifact.evidenceIntegrity ===
                            "N/A"

                                ? "N/A"

                                : `${escapeHtml(
                                    artifact.evidenceIntegrity
                                )}%`
                        }
                    </strong>
                </div>

                <div>
                    <span>Observed / Intact</span>
                    <strong>
                        ${escapeHtml(
                            artifact.observedIntact ??
                            0
                        )}
                    </strong>
                </div>

                <div>
                    <span>Suspected / Anomalous</span>
                    <strong>
                        ${escapeHtml(
                            artifact.suspectedAnomalous ??
                            0
                        )}
                    </strong>
                </div>

                <div>
                    <span>Unknown / Unrecoverable</span>
                    <strong>
                        ${escapeHtml(
                            artifact.unknownUnrecoverable ??
                            0
                        )}
                    </strong>
                </div>

            </div>

            <div class="modal-explanation">

                <h4>
                    Explanation
                </h4>

                <p>
                    ${escapeHtml(
                        artifact.explanation ||
                        "No explanation available."
                    )}
                </p>

            </div>

            ${
                explanations.length
                    ? `

                    <div class="modal-explanation">

                        <h4>
                            Explainability
                        </h4>

                        <ul>
                            ${explanations
                                .map(
                                    (item) =>
                                        `<li>${escapeHtml(
                                            item
                                        )}</li>`
                                )
                                .join("")}
                        </ul>

                    </div>

                    `
                    : ""
            }

        `;
    }


    modal.hidden =
        false;

    modal.classList.add(
        "open"
    );
}


/* =========================================================
   CLOSE MODALS
========================================================= */

function closeModal(
    modal
) {

    if (!modal) {
        return;
    }


    modal.classList.remove(
        "open"
    );


    modal.hidden =
        true;
}


function setupModal() {

    document
        .querySelectorAll(
            "[data-modal-close]"
        )
        .forEach(
            (button) => {

                button.addEventListener(
                    "click",
                    () => {

                        const modal =
                            button.closest(
                                ".modal"
                            );

                        closeModal(
                            modal
                        );
                    }
                );
            }
        );


    document
        .querySelectorAll(
            ".modal"
        )
        .forEach(
            (modal) => {

                modal.addEventListener(
                    "click",
                    (event) => {

                        if (
                            event.target ===
                            modal
                        ) {

                            closeModal(
                                modal
                            );
                        }
                    }
                );
            }
        );


    document.addEventListener(
        "keydown",
        (event) => {

            if (
                event.key !==
                "Escape"
            ) {
                return;
            }


            document
                .querySelectorAll(
                    ".modal.open"
                )
                .forEach(
                    (modal) =>
                        closeModal(
                            modal
                        )
                );
        }
    );
}


/* =========================================================
   EXPLAINABILITY PANEL
========================================================= */

function renderExplainability() {

    const artifact =
        state.artifacts[0];


    const what =
        document.getElementById(
            "explainWhat"
        );

    const why =
        document.getElementById(
            "explainWhy"
        );

    const limitation =
        document.getElementById(
            "explainLimitation"
        );


    if (!artifact) {
        return;
    }


    if (what) {

        what.textContent =
            artifact.explanation ||
            "Evidence was analyzed independently.";
    }


    if (why) {

        const reasons =
            Array.isArray(
                artifact.explainability
            )
                ? artifact.explainability
                : [];


        why.innerHTML =
            reasons.length

                ? `<ul>${reasons
                    .slice(
                        0,
                        6
                    )
                    .map(
                        (reason) =>
                            `<li>${escapeHtml(
                                reason
                            )}</li>`
                    )
                    .join("")}</ul>`

                : "No additional reasoning was supplied by the backend.";
    }


    if (limitation) {

        limitation.textContent =
            "No original reference evidence was supplied. Anvaya can classify and validate surviving evidence, but it cannot determine the exact original content of missing or unrecoverable regions from the damaged file alone.";
    }
}


/* =========================================================
   CORRUPTION / INTEGRITY SUMMARY
========================================================= */

function renderIntegritySummary() {

    const stats =
        state.stats ||
        {};


    const observed =
        Number(
            stats.observedIntact ||
            0
        );

    const suspected =
        Number(
            stats.suspectedAnomalous ||
            0
        );

    const unknown =
        Number(
            stats.unknownUnrecoverable ||
            0
        );


    const observedElement =
        document.getElementById(
            "observedIntactValue"
        );

    const suspectedElement =
        document.getElementById(
            "suspectedAnomalousValue"
        );

    const unknownElement =
        document.getElementById(
            "unknownUnrecoverableValue"
        );


    if (observedElement) {

        observedElement.textContent =
            observed;
    }


    if (suspectedElement) {

        suspectedElement.textContent =
            suspected;
    }


    if (unknownElement) {

        unknownElement.textContent =
            unknown;
    }


    const anomalyElement =
        document.getElementById(
            "anomalyStatus"
        );


    if (anomalyElement) {

        const anomaly =
            Number(
                suspected
            );


        if (anomaly > 0) {

            anomalyElement.textContent =
                "Elevated";

        } else {

            anomalyElement.textContent =
                "Normal";
        }
    }
}


/* =========================================================
   RENDER ALL
========================================================= */

function renderAll() {

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

    renderExplainability();

    renderIntegritySummary();
}


/* =========================================================
   EMPTY DASHBOARD
========================================================= */

function loadEmptyDashboard() {

    state.mode =
        "demo";

    state.case =
        MOCK_DATA.caseInfo;

    state.stats =
        MOCK_DATA.stats;

    state.artifacts =
        MOCK_DATA.artifacts;

    state.fragments =
        MOCK_DATA.fragments;

    state.timeline =
        MOCK_DATA.timeline;

    state.audit = {

        caseId:
            MOCK_DATA.caseInfo.id,

        evidenceId:
            MOCK_DATA.caseInfo.evidenceId,

        sha256:
            MOCK_DATA.caseInfo.sha256,

        inputTimestamp:
            MOCK_DATA.caseInfo.inputTimestamp,

        processingTimestamp:
            MOCK_DATA.caseInfo.processingTimestamp,

        operationCount:
            MOCK_DATA.caseInfo.operationCount,

        originalHash:
            MOCK_DATA.caseInfo.originalHash,

        recoveredHash:
            MOCK_DATA.caseInfo.recoveredArtifactHash,

        provenanceStatus:
            MOCK_DATA.caseInfo.provenanceStatus
    };


    renderAll();
}


/* =========================================================
   RESET DASHBOARD
========================================================= */

function resetDashboard() {

    state.case =
        null;

    state.stats =
        null;

    state.artifacts =
        [];

    state.fragments =
        [];

    state.timeline =
        [];

    state.audit =
        null;

    state.selectedFragment =
        null;

    state.selectedArtifact =
        null;

    apiRequestFailed =
        false;


    /*
     Clear common dashboard values.
    */

    const ids = [

        "caseIdLabel",

        "fileCount",

        "recoveredCount",

        "confidence",

        "fragmentCount",

        "selectedFragmentId",

        "selectedFragmentState",

        "selectedFragmentType",

        "selectedFragmentHash",

        "selectedFragmentReasoning",

        "selectedFragmentSize",

        "auditCaseId",

        "auditEvidenceId",

        "auditHash",

        "auditInputTime",

        "auditProcessTime",

        "auditOps",

        "auditOriginalHash",

        "auditRecoveredHash",

        "auditProvenance"
    ];


    ids.forEach(
        (id) => {

            const element =
                document.getElementById(
                    id
                );


            if (element) {

                element.textContent =
                    "—";
            }
        }
    );


    const fragmentGraph =
        document.getElementById(
            "fragmentGraph"
        );


    if (fragmentGraph) {

        fragmentGraph.innerHTML =
            "";
    }


    const artifactTable =
        document.getElementById(
            "artifactTableBody"
        );


    if (artifactTable) {

        artifactTable.innerHTML =
            "";
    }


    const timeline =
        document.getElementById(
            "timelineList"
        );


    if (timeline) {

        timeline.innerHTML =
            "";
    }
}


/* =========================================================
   UPLOAD STATUS
========================================================= */

function setUploadStatus(
    message,
    type = "info"
) {

    uploadStatus =
        document.getElementById(
            "uploadStatus"
        );


    if (!uploadStatus) {
        return;
    }


    uploadStatus.textContent =
        message;


    uploadStatus.dataset.status =
        type;
}


/* =========================================================
   FILE DISPLAY
========================================================= */

function getFileIcon(
    file
) {

    if (!file) {
        return "📄";
    }


    const extension =
        file.name
            .split(".")
            .pop()
            .toLowerCase();


    switch (
        extension
    ) {

        case "pdf":

            return "📕";


        case "jpg":
        case "jpeg":
        case "png":

            return "🖼️";


        case "docx":

            return "📘";


        case "xlsx":

            return "📗";


        case "zip":

            return "🗜️";


        case "sqlite":
        case "db":

            return "🗄️";


        case "txt":

            return "📄";


        default:

            return "📦";
    }
}


function updateFileDisplay(
    file
) {

    const dropZone =
        document.getElementById(
            "fileDropZone"
        );

    const selected =
        document.getElementById(
            "fileSelected"
        );

    const fileName =
        document.getElementById(
            "selectedFileName"
        );

    const fileSize =
        document.getElementById(
            "selectedFileSize"
        );

    const fileIcon =
        document.getElementById(
            "fileIcon"
        );

    const analyzeButton =
        document.getElementById(
            "analyzeBtn"
        );


    if (!file) {

        if (dropZone) {

            dropZone.hidden =
                false;
        }


        if (selected) {

            selected.hidden =
                true;
        }


        if (fileName) {

            fileName.textContent =
                "No file selected";
        }


        if (fileSize) {

            fileSize.textContent =
                "";
        }


        if (fileIcon) {

            fileIcon.textContent =
                "📄";
        }


        if (analyzeButton) {

            analyzeButton.disabled =
                true;
        }


        setUploadStatus(
            "Select an evidence file to begin.",
            "info"
        );


        return;
    }


    if (dropZone) {

        dropZone.hidden =
            false;
    }


    if (selected) {

        selected.hidden =
            false;
    }


    if (fileName) {

        fileName.textContent =
            file.name;
    }


    if (fileSize) {

        fileSize.textContent =
            formatBytes(
                file.size
            );
    }


    if (fileIcon) {

        fileIcon.textContent =
            getFileIcon(
                file
            );
    }


    if (analyzeButton) {

        analyzeButton.disabled =
            false;
    }

    const recoverButton = document.getElementById("recoverBtn");
    if (recoverButton) {
        recoverButton.disabled = false;
    }


    setUploadStatus(
        "Evidence file selected. Click Analyze Evidence or Recover Evidence to begin.",
        "ready"
    );
}


/* =========================================================
   EVIDENCE UPLOAD
========================================================= */

function setupEvidenceUpload() {

    const fileInput =
        document.getElementById(
            "evidenceFile"
        );

    const selectedFileName =
        document.getElementById(
            "selectedFileName"
        );

    const selectedFileSize =
        document.getElementById(
            "selectedFileSize"
        );

    const fileIcon =
        document.getElementById(
            "fileIcon"
        );

    const fileSelected =
        document.getElementById(
            "fileSelected"
        );

    const fileRemove =
        document.getElementById(
            "fileRemove"
        );

    const dropZone =
        document.getElementById(
            "fileDropZone"
        );

    const analyzeButton =
        document.getElementById(
            "analyzeBtn"
        );


    if (!fileInput) {

        console.error(
            "Anvaya: #evidenceFile not found."
        );

        return;
    }


    /*
     IMPORTANT FIX:
     There is intentionally NO second click
     handler on the drop zone.

     The old handler cleared the file immediately
     after the label opened the browser picker.
    */


    fileInput.addEventListener(
        "change",
        () => {

            const file =
                fileInput.files?.[0] ||
                null;


            console.log(
                "Anvaya selected file:",
                file
            );


            updateFileDisplay(
                file
            );
        }
    );


    if (dropZone) {

        dropZone.addEventListener(
            "dragover",
            (event) => {

                event.preventDefault();

                dropZone.classList.add(
                    "dragover"
                );
            }
        );


        dropZone.addEventListener(
            "dragleave",
            () => {

                dropZone.classList.remove(
                    "dragover"
                );
            }
        );


        dropZone.addEventListener(
            "drop",
            (event) => {

                event.preventDefault();

                dropZone.classList.remove(
                    "dragover"
                );


                const file =
                    event.dataTransfer
                        ?.files?.[0] ||
                    null;


                if (!file) {
                    return;
                }


                try {

                    const transfer =
                        new DataTransfer();

                    transfer.items.add(
                        file
                    );

                    fileInput.files =
                        transfer.files;

                } catch (error) {

                    console.warn(
                        "Could not assign dropped file to input:",
                        error
                    );
                }


                updateFileDisplay(
                    file
                );
            }
        );
    }


    if (fileRemove) {

        fileRemove.addEventListener(
            "click",
            (event) => {

                event.preventDefault();

                event.stopPropagation();


                fileInput.value =
                    "";


                updateFileDisplay(
                    null
                );


                resetDashboard();


                setUploadStatus(
                    "Evidence selection cleared.",
                    "info"
                );
            }
        );
    }


    if (analyzeButton) {

        analyzeButton.addEventListener(
            "click",
            async () => {

                const file =
                    fileInput.files?.[0];


                if (!file) {

                    setUploadStatus(
                        "Please select an evidence file first.",
                        "error"
                    );

                    return;
                }


                analyzeButton.disabled =
                    true;


                analyzeButton.dataset.originalText =
                    analyzeButton.textContent;


                analyzeButton.textContent =
                    "Analyzing…";


                apiRequestFailed =
                    false;


                state.mode =
                    "live";


                renderModeIndicator();


                setUploadStatus(
                    "Uploading evidence and running forensic analysis…",
                    "loading"
                );


                try {

                    const response =
                        await analyzeEvidenceFile(
                            file
                        );


                    console.log(
                        "Anvaya backend response:",
                        response
                    );


                    const normalized =
                        normalizeBackendResponse(
                            response
                        );


                    state.rawResponse =
                        response;

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


                    renderAll();


                    setUploadStatus(
                        "Analysis completed successfully.",
                        "success"
                    );


                    /*
                     Scroll to the results.
                    */

                    const dashboard =
                        document.getElementById(
                            "dashboard"
                        );


                    if (dashboard) {

                        dashboard.scrollIntoView({
                            behavior:
                                "smooth",
                            block:
                                "start"
                        });
                    }

                } catch (error) {

                    console.error(
                        "Anvaya analysis failed:",
                        error
                    );


                    apiRequestFailed =
                        true;

                    state.mode =
                        "error";


                    renderModeIndicator();


                    setUploadStatus(
                        `Analysis failed: ${
                            error.message ||
                            "Unknown backend error"
                        }`,
                        "error"
                    );


                    /*
                     IMPORTANT:
                     Do NOT silently replace the failed
                     real analysis with demo data.
                    */

                    alert(
                        `Anvaya could not analyze the evidence.\n\n${
                            error.message ||
                            "Check that the FastAPI backend is running on port 8001."
                        }`
                    );

                } finally {

                    analyzeButton.disabled =
                        false;


                    analyzeButton.textContent =
                        analyzeButton.dataset
                            .originalText ||
                        "Analyze Evidence";
                }
}
        );
    }


    // Recover button handler
    const recoverButton = document.getElementById("recoverBtn");
    if (recoverButton) {
        recoverButton.addEventListener("click", async () => {
            const file = fileInput.files?.[0];

            if (!file) {
                setUploadStatus("Please select an evidence file first.", "error");
                return;
            }

            recoverButton.disabled = true;
            recoverButton.dataset.originalText = recoverButton.textContent;
            recoverButton.textContent = "Recovering…";

            apiRequestFailed = false;
            state.mode = "live";
            renderModeIndicator();

            setUploadStatus("Uploading evidence and running recovery pipeline…", "loading");

            try {
                const response = await recoverEvidenceFile(file);

                console.log("Anvaya recovery response:", response);

                const normalized = normalizeRecoveryResponse(response);

                state.rawResponse = response;
                state.mode = "live";
                state.case = normalized.caseInfo;
                state.stats = normalized.stats;
                state.artifacts = normalized.artifacts;
                state.fragments = normalized.fragments;
                state.timeline = normalized.timeline;
                state.audit = normalized.audit;

                renderDashboard();
                renderEvidence();
                renderClassification();
                renderFragments();
                renderTimeline();
                renderAudit();

                setUploadStatus("Recovery complete.", "success");

            } catch (error) {
                console.error("Recovery error:", error);
                apiRequestFailed = true;
                setUploadStatus(
                    `Recovery failed: ${error.message || "Unknown error"}`,
                    "error"
                );

                alert(
                    `Anvaya could not recover the evidence.\n\n${error.message || "Check that the FastAPI backend is running on port 8000."}`
                );

            } finally {
                recoverButton.disabled = false;
                recoverButton.textContent = recoverButton.dataset.originalText || "Recover Evidence";
            }
        });
    }


    /*
     Initial state.
     */

    updateFileDisplay(
        fileInput.files?.[0] ||
        null
    );
}


/* =========================================================
   SECTION NAVIGATION
========================================================= */

function setupSectionNavigation() {

    const links =
        document.querySelectorAll(
            "[data-section]"
        );


    links.forEach(
        (link) => {

            link.addEventListener(
                "click",
                (event) => {

                    const targetId =
                        link.dataset.section;


                    if (!targetId) {
                        return;
                    }


                    const target =
                        document.getElementById(
                            targetId
                        );


                    if (!target) {
                        return;
                    }


                    event.preventDefault();


                    target.scrollIntoView({
                        behavior:
                            "smooth",
                        block:
                            "start"
                    });


                    links.forEach(
                        (item) => {

                            item.classList.remove(
                                "active"
                            );
                        }
                    );


                    link.classList.add(
                        "active"
                    );
                }
            );
        }
    );
}


/* =========================================================
   PDF REPORT EXPORT
========================================================= */

function exportEvidenceReport() {

    if (
        !state.rawResponse &&
        state.mode !==
        "demo"
    ) {

        alert(
            "No analysis result is available to export."
        );

        return;
    }


    if (
        !window.jspdf ||
        !window.jspdf.jsPDF
    ) {

        alert(
            "PDF export library is not loaded. Check the jsPDF CDN in index.html."
        );

        return;
    }


    const {
        jsPDF
    } =
        window.jspdf;


    const doc =
        new jsPDF();


    const caseInfo =
        state.case ||
        {};

    const stats =
        state.stats ||
        {};


    const now =
        new Date();


    const dateText =
        now
            .toISOString()
            .slice(
                0,
                10
            );


    /*
     Header
    */

    doc.setFontSize(
        20
    );

    doc.setFont(
        "helvetica",
        "bold"
    );

    doc.text(
        "ANVAYA",
        20,
        20
    );


    doc.setFontSize(
        11
    );

    doc.setFont(
        "helvetica",
        "normal"
    );

    doc.text(
        "Explainable Digital Evidence Analysis Report",
        20,
        28
    );


    doc.line(
        20,
        33,
        190,
        33
    );


    /*
     Case information
    */

    doc.setFontSize(
        13
    );

    doc.setFont(
        "helvetica",
        "bold"
    );

    doc.text(
        "Case Information",
        20,
        45
    );


    doc.setFontSize(
        10
    );

    doc.setFont(
        "helvetica",
        "normal"
    );


    const caseRows = [

        [
            "Case ID",
            caseInfo.id ||
            "N/A"
        ],

        [
            "Evidence",
            caseInfo.evidenceId ||
            "N/A"
        ],

        [
            "SHA-256",
            caseInfo.sha256 ||
            "N/A"
        ],

        [
            "Analysis Mode",
            state.mode ===
            "live"
                ? "Live Backend"
                : "Demo"
        ],

        [
            "Processing Time",
            formatTimestamp(
                caseInfo.processingTimestamp
            )
        ]

    ];


    if (
        typeof doc.autoTable ===
        "function"
    ) {

        doc.autoTable({

            startY:
                50,

            head: [
                [
                    "Field",
                    "Value"
                ]
            ],

            body:
                caseRows,

            theme:
                "grid",

            styles: {
                fontSize:
                    8
            }
        });

    } else {

        let y =
            52;


        caseRows.forEach(
            ([key, value]) => {

                doc.text(
                    `${key}:`,
                    20,
                    y
                );

                doc.text(
                    String(
                        value
                    ).slice(
                        0,
                        100
                    ),
                    70,
                    y
                );

                y +=
                    7;
            }
        );
    }


    /*
     Evidence integrity
    */

    const startY =
        typeof doc.lastAutoTable !==
        "undefined"

            ? doc.lastAutoTable.finalY +
              15

            : 105;


    doc.setFontSize(
        13
    );

    doc.setFont(
        "helvetica",
        "bold"
    );

    doc.text(
        "Evidence Integrity",
        20,
        startY
    );


    const integrityRows = [

        [
            "Evidence Integrity",
            stats.evidenceIntegrity ===
            "N/A"

                ? "N/A"

                : `${stats.evidenceIntegrity}%`
        ],

        [
            "Observed / Intact",
            String(
                stats.observedIntact ??
                0
            )
        ],

        [
            "Suspected / Anomalous",
            String(
                stats.suspectedAnomalous ??
                0
            )
        ],

        [
            "Unknown / Unrecoverable",
            String(
                stats.unknownUnrecoverable ??
                0
            )
        ],

        [
            "Fragments Analyzed",
            String(
                stats.totalFragments ??
                0
            )
        ],

        [
            "Anomaly Status",
            stats.anomalyScore ||
            "N/A"
        ]

    ];


    if (
        typeof doc.autoTable ===
        "function"
    ) {

        doc.autoTable({

            startY:
                startY + 5,

            head: [
                [
                    "Metric",
                    "Result"
                ]
            ],

            body:
                integrityRows,

            theme:
                "grid",

            styles: {
                fontSize:
                    8
            }
        });
    }


    /*
     Important limitation statement.
    */

    const limitationY =
        typeof doc.lastAutoTable !==
        "undefined"

            ? doc.lastAutoTable.finalY +
              15

            : startY + 55;


    doc.setFontSize(
        12
    );

    doc.setFont(
        "helvetica",
        "bold"
    );

    doc.text(
        "Interpretation",
        20,
        limitationY
    );


    doc.setFontSize(
        9
    );

    doc.setFont(
        "helvetica",
        "normal"
    );


    const disclaimer =
        "This report describes observable evidence in the submitted file. No original reference evidence was supplied. Unknown or anomalous regions are not presented as recovered original content.";


    const wrapped =
        doc.splitTextToSize(
            disclaimer,
            170
        );


    doc.text(
        wrapped,
        20,
        limitationY + 7
    );


    /*
     Audit
    */

    const auditY =
        limitationY +
        7 +
        wrapped.length *
        4 +
        12;


    doc.setFontSize(
        12
    );

    doc.setFont(
        "helvetica",
        "bold"
    );

    doc.text(
        "Provenance",
        20,
        auditY
    );


    doc.setFontSize(
        9
    );

    doc.setFont(
        "helvetica",
        "normal"
    );


    doc.text(
        state.audit?.provenanceStatus ||
        "Not available",
        20,
        auditY + 7
    );


    /*
     Footer
    */

    doc.setFontSize(
        8
    );


    doc.text(
        `Generated by Anvaya • ${now.toLocaleString()}`,
        20,
        285
    );


    const filename =
        `anvaya-evidence-report-${
            state.case?.id ||
            "case"
        }-${dateText}.pdf`;


    doc.save(
        filename
    );
}


/* =========================================================
   RESET / DEMO
========================================================= */

function setupResetControls() {

    document
        .querySelectorAll(
            "[data-reset-dashboard]"
        )
        .forEach(
            (button) => {

                button.addEventListener(
                    "click",
                    () => {

                        const fileInput =
                            document.getElementById(
                                "evidenceFile"
                            );


                        if (fileInput) {

                            fileInput.value =
                                "";
                        }


                        updateFileDisplay(
                            null
                        );


                        loadEmptyDashboard();
                    }
                );
            }
        );
}


/* =========================================================
   COPY HASH
========================================================= */

function setupCopyButtons() {

    document
        .querySelectorAll(
            "[data-copy-target]"
        )
        .forEach(
            (button) => {

                button.addEventListener(
                    "click",
                    async () => {

                        const targetId =
                            button.dataset
                                .copyTarget;


                        const target =
                            document.getElementById(
                                targetId
                            );


                        if (!target) {
                            return;
                        }


                        const text =
                            target.textContent
                                .trim();


                        if (!text) {
                            return;
                        }


                        try {

                            await navigator
                                .clipboard
                                .writeText(
                                    text
                                );


                            const oldText =
                                button.textContent;


                            button.textContent =
                                "Copied";


                            setTimeout(
                                () => {

                                    button.textContent =
                                        oldText;

                                },
                                1200
                            );

                        } catch (error) {

                            console.warn(
                                "Clipboard copy failed:",
                                error
                            );
                        }
                    }
                );
            }
        );
}


/* =========================================================
   MOBILE MENU
========================================================= */

function setupMobileMenu() {

    const button =
        document.getElementById(
            "mobileMenuButton"
        );

    const navigation =
        document.getElementById(
            "mainNavigation"
        );


    if (
        !button ||
        !navigation
    ) {
        return;
    }


    button.addEventListener(
        "click",
        () => {

            navigation.classList.toggle(
                "open"
            );
        }
    );
}


/* =========================================================
   INITIALIZE DASHBOARD
========================================================= */

function initializeDashboard() {

    console.log(
        "Anvaya dashboard initializing..."
    );


    apiRequestFailed =
        false;


    loadEmptyDashboard();


    setupEvidenceUpload();

    setupSectionNavigation();

    setupModal();

    setupResetControls();

    setupCopyButtons();

    setupMobileMenu();


    const exportButton =
        document.getElementById(
            "exportReportBtn"
        );


    if (exportButton) {

        exportButton.addEventListener(
            "click",
            exportEvidenceReport
        );
    }


    console.log(
        "Anvaya dashboard ready."
    );
}


/* =========================================================
   DOM READY
========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    initializeDashboard
);