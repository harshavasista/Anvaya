/**
 * ANVAYA — Digital Evidence Analysis & Forensic Reconstruction
 * Frontend Application Controller
 */

(function () {
    'use strict';

    // API Base URL: defaults to backend on port 8000
    const API_BASE = window.location.port === '8000' ? '' : 'http://127.0.0.1:8000';

    // DOM Elements
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const uploadPrompt = document.getElementById('uploadPrompt');
    const fileSelectedInfo = document.getElementById('fileSelectedInfo');
    const selectedFileName = document.getElementById('selectedFileName');
    const selectedFileMeta = document.getElementById('selectedFileMeta');
    const btnChangeFile = document.getElementById('btnChangeFile');
    const btnAnalyze = document.getElementById('btnAnalyze');
    const analysisProgress = document.getElementById('analysisProgress');
    const errorBanner = document.getElementById('errorBanner');
    const errorMessage = document.getElementById('errorMessage');
    const resultsContainer = document.getElementById('resultsContainer');

    // State
    let currentSelectedFile = null;
    let currentCaseData = null;

    // Initialize Event Listeners
    function init() {
        // Drag & Drop
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove('dragover');
            });
        });

        dropZone.addEventListener('drop', (e) => {
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                handleFileSelection(e.dataTransfer.files[0]);
            }
        });

        dropZone.addEventListener('click', (e) => {
            if (e.target !== btnChangeFile && !btnChangeFile.contains(e.target)) {
                fileInput.click();
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files && e.target.files.length > 0) {
                handleFileSelection(e.target.files[0]);
            }
        });

        btnChangeFile.addEventListener('click', (e) => {
            e.stopPropagation();
            fileInput.value = '';
            fileInput.click();
        });

        btnAnalyze.addEventListener('click', executeAnalysis);
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function handleFileSelection(file) {
        if (!file) return;

        // 100 MB Limit check
        if (file.size > 100 * 1024 * 1024) {
            showError('Selected file exceeds the 100 MB forensic ingestion limit.');
            return;
        }

        hideError();
        currentSelectedFile = file;

        // Update UI
        selectedFileName.textContent = file.name;
        selectedFileMeta.textContent = `${formatBytes(file.size)} • ${file.type || 'Binary'}`;

        uploadPrompt.classList.add('hidden');
        fileSelectedInfo.classList.remove('hidden');
        btnAnalyze.disabled = false;
    }

    function showError(msg) {
        errorMessage.textContent = msg;
        errorBanner.classList.remove('hidden');
    }

    function hideError() {
        errorBanner.classList.add('hidden');
    }

    async function executeAnalysis() {
        if (!currentSelectedFile) return;

        hideError();
        btnAnalyze.disabled = true;
        analysisProgress.classList.remove('hidden');
        resultsContainer.classList.add('hidden');

        const formData = new FormData();
        formData.append('file', currentSelectedFile);

        try {
            const response = await fetch(`${API_BASE}/api/case/analyze`, {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (!response.ok) {
                const errMsg = (data && data.error && data.error.message) 
                    ? data.error.message 
                    : `Forensic analysis request failed with HTTP ${response.status}`;
                throw new Error(errMsg);
            }

            currentCaseData = data;
            renderResults(data);
            resultsContainer.classList.remove('hidden');
        } catch (err) {
            console.error('Forensic Analysis Error:', err);
            showError(err.message || 'Connection failure. Ensure the ANVAYA backend is active on port 8000.');
        } finally {
            analysisProgress.classList.add('hidden');
            btnAnalyze.disabled = false;
        }
    }

    function getBadgeClassForStatus(status) {
        switch (status) {
            case 'HEALTHY':
            case 'VALIDATED':
            case 'RECOVERED':
            case 'REPAIRED':
                return 'badge-healthy';
            case 'PARTIALLY_CORRUPTED':
            case 'PARTIALLY_RECOVERED':
            case 'PARTIALLY_VALIDATED':
                return 'badge-warning';
            case 'CORRUPTED':
            case 'SEVERELY_CORRUPTED':
            case 'VALIDATION_FAILED':
            case 'UNRECOVERABLE':
                return 'badge-corrupted';
            default:
                return 'badge-neutral';
        }
    }

    async function renderPreviewContent(url, container, fileType) {
        container.innerHTML = '';
        if (!url) {
            container.innerHTML = '<div class="preview-placeholder">No preview available</div>';
            return;
        }

        const fullUrl = url.startsWith('http') ? url : `${API_BASE}${url}`;

        if (fileType === 'PDF') {
            // PDF Rendering via Iframe
            const iframe = document.createElement('iframe');
            iframe.className = 'preview-iframe';
            iframe.src = `${fullUrl}#toolbar=0&navpanes=0`;
            iframe.type = 'application/pdf';
            iframe.title = 'PDF Forensic Preview';
            container.appendChild(iframe);
        } else if (fileType === 'TXT' || fileType === 'CSV' || fileType === 'JSON') {
            // Text / JSON / CSV: fetch text and display in monospace block
            try {
                const res = await fetch(fullUrl);
                const txt = await res.text();
                const pre = document.createElement('pre');
                pre.className = 'preview-text-block';
                if (fileType === 'JSON') {
                    try {
                        const parsed = JSON.parse(txt);
                        pre.textContent = JSON.stringify(parsed, null, 2);
                    } catch (e) {
                        pre.textContent = txt;
                    }
                } else {
                    pre.textContent = txt;
                }
                container.appendChild(pre);
            } catch (e) {
                container.innerHTML = `<div class="preview-placeholder">Failed to load text preview: ${e.message}</div>`;
            }
        } else if (fileType === 'PNG' || fileType === 'JPEG') {
            // Image preview
            const img = document.createElement('img');
            img.className = 'preview-img';
            img.src = fullUrl;
            img.alt = 'Evidence Image Preview';
            container.appendChild(img);
        } else {
            // Unsupported binary container
            container.innerHTML = `
                <div class="preview-placeholder">
                    <p>Binary container preview not supported inline.</p>
                    <p class="file-meta-row" style="margin-top:8px;">Format: ${fileType}</p>
                </div>
            `;
        }
    }

    function renderResults(data) {
        // 1. File Information Strip
        document.getElementById('caseIdBadge').textContent = data.case.case_id;
        document.getElementById('valFilename').textContent = data.evidence.filename;
        document.getElementById('valFileType').textContent = data.evidence.file_type;
        document.getElementById('valFileSize').textContent = formatBytes(data.evidence.size_bytes);
        document.getElementById('valMimeType').textContent = data.evidence.mime_type;
        document.getElementById('valSha256').textContent = data.evidence.sha256;

        // 2. FORENSIC COMPARISON (SIDE-BY-SIDE)
        const hasReference = data.preview.reference_url && data.reference_metadata && data.reference_metadata.available;
        const noRefNotice = document.getElementById('noReferenceNotice');
        const leftPanelTitle = document.getElementById('leftPanelTitle');
        const leftPanelBadge = document.getElementById('leftPanelBadge');
        const leftPanelHash = document.getElementById('leftPanelHash');
        const leftContainer = document.getElementById('leftPreviewContainer');

        const rightPanelTitle = document.getElementById('rightPanelTitle');
        const rightPanelBadge = document.getElementById('rightPanelBadge');
        const rightPanelHash = document.getElementById('rightPanelHash');
        const rightContainer = document.getElementById('rightPreviewContainer');

        if (hasReference) {
            noRefNotice.classList.add('hidden');
            leftPanelTitle.textContent = 'ORIGINAL / REFERENCE EXHIBIT';
            leftPanelBadge.textContent = 'INTACT / REFERENCE';
            leftPanelBadge.className = 'status-badge badge-healthy';
            leftPanelHash.textContent = data.reference_metadata.sha256 || '—';
            renderPreviewContent(data.preview.reference_url, leftContainer, data.evidence.file_type);

            rightPanelTitle.textContent = 'CORRUPTED UPLOADED EVIDENCE';
            rightPanelBadge.textContent = data.classification.status;
            rightPanelBadge.className = `status-badge ${getBadgeClassForStatus(data.classification.status)}`;
            rightPanelHash.textContent = data.evidence.sha256;
            renderPreviewContent(data.preview.corrupted_url, rightContainer, data.evidence.file_type);
        } else {
            noRefNotice.classList.remove('hidden');
            leftPanelTitle.textContent = 'UPLOADED EVIDENCE EXHIBIT';
            leftPanelBadge.textContent = data.classification.status;
            leftPanelBadge.className = `status-badge ${getBadgeClassForStatus(data.classification.status)}`;
            leftPanelHash.textContent = data.evidence.sha256;
            renderPreviewContent(data.preview.uploaded_url, leftContainer, data.evidence.file_type);

            rightPanelTitle.textContent = 'STATUS INSPECTION VIEW';
            rightPanelBadge.textContent = data.classification.status;
            rightPanelBadge.className = `status-badge ${getBadgeClassForStatus(data.classification.status)}`;
            rightPanelHash.textContent = data.evidence.sha256;
            renderPreviewContent(data.preview.corrupted_url, rightContainer, data.evidence.file_type);
        }

        // 3. Corruption & Integrity Analysis
        const corruptionBadge = document.getElementById('corruptionStatusBadge');
        corruptionBadge.textContent = data.classification.status;
        corruptionBadge.className = `status-badge ${getBadgeClassForStatus(data.classification.status)}`;

        const reasonsList = document.getElementById('corruptionReasonsList');
        reasonsList.innerHTML = '';
        if (data.classification.reasons && data.classification.reasons.length > 0) {
            data.classification.reasons.forEach(reason => {
                const li = document.createElement('li');
                li.textContent = reason;
                reasonsList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = 'File passed all applicable forensic integrity and structure checks without error.';
            li.style.borderLeftColor = 'var(--color-green)';
            reasonsList.appendChild(li);
        }

        // Structural Checks List
        const checksList = document.getElementById('checksList');
        checksList.innerHTML = '';
        if (data.corruption.validation_checks && data.corruption.validation_checks.length > 0) {
            data.corruption.validation_checks.forEach(chk => {
                const item = document.createElement('div');
                item.className = 'check-item';
                item.innerHTML = `
                    <span>${chk.name}: <small style="color:var(--text-secondary);">${chk.details}</small></span>
                    <span class="${chk.passed ? 'check-pass' : 'check-fail'}">${chk.passed ? 'PASSED' : 'FAILED'}</span>
                `;
                checksList.appendChild(item);
            });
        }

        // Affected Regions & Fragments
        const tagsContainer = document.getElementById('affectedRegionsTags');
        tagsContainer.innerHTML = '';
        const affectedRegions = data.corruption.affected_regions || [];
        const affectedFragments = data.corruption.affected_fragments || [];

        if (affectedRegions.length === 0 && affectedFragments.length === 0) {
            tagsContainer.innerHTML = '<span class="region-tag" style="background:var(--color-green-bg);color:var(--color-green);border-color:var(--color-green);">No Affected Byte Regions Detected</span>';
        } else {
            affectedRegions.forEach(reg => {
                const tag = document.createElement('span');
                tag.className = 'region-tag';
                tag.textContent = `Offset ${reg.offset} (${reg.length} bytes): ${reg.reason}`;
                tagsContainer.appendChild(tag);
            });
            if (affectedFragments.length > 0) {
                const fragTag = document.createElement('span');
                fragTag.className = 'region-tag';
                fragTag.style.background = 'var(--color-yellow-bg)';
                fragTag.style.color = 'var(--color-yellow)';
                fragTag.style.borderColor = 'var(--color-yellow)';
                fragTag.textContent = `Affected 4KB Fragments: [${affectedFragments.join(', ')}]`;
                tagsContainer.appendChild(fragTag);
            }
        }

        // 4. Recovery Audit
        const recoveryBadge = document.getElementById('recoveryStatusBadge');
        recoveryBadge.textContent = data.recovery.status;
        recoveryBadge.className = `status-badge ${getBadgeClassForStatus(data.recovery.status)}`;

        document.getElementById('statRecoveredFrags').textContent = data.recovery.recovered_fragments || 0;
        document.getElementById('statMissingFrags').textContent = data.recovery.missing_fragments || 0;
        document.getElementById('statUnresolvedFrags').textContent = data.recovery.unresolved_fragments || 0;
        document.getElementById('statRecoveryMethods').textContent = (data.recovery.methods && data.recovery.methods.length) || 0;

        const methodsList = document.getElementById('recoveryMethodsList');
        if (data.recovery.methods && data.recovery.methods.length > 0) {
            methodsList.textContent = data.recovery.methods.join(', ');
        } else {
            methodsList.textContent = 'None required / Available';
        }

        // 5. RESTORED / RECOVERED CANDIDATE PREVIEW
        const restoredSection = document.getElementById('restoredSection');
        const restoredContainer = document.getElementById('restoredPreviewContainer');
        const candidateValidationBadge = document.getElementById('candidateValidationBadge');
        const candidateValidationText = document.getElementById('candidateValidationText');
        const candidateSha256 = document.getElementById('candidateSha256');

        if (data.recovery.candidate_url) {
            restoredSection.classList.remove('hidden');
            candidateValidationBadge.textContent = data.validation.status;
            candidateValidationBadge.className = `status-badge ${getBadgeClassForStatus(data.validation.status)}`;
            candidateValidationText.textContent = data.validation.status;
            candidateSha256.textContent = data.recovery.recovered_sha256 || '—';
            renderPreviewContent(data.recovery.candidate_url, restoredContainer, data.evidence.file_type);
        } else {
            // Hide candidate preview or display explanation
            if (data.recovery.status === 'NOT_REQUIRED') {
                restoredSection.classList.add('hidden');
            } else {
                restoredSection.classList.remove('hidden');
                candidateValidationBadge.textContent = 'UNRECOVERABLE';
                candidateValidationBadge.className = 'status-badge badge-corrupted';
                candidateValidationText.textContent = 'RESTORE NOT SAFE / UNRECOVERABLE';
                candidateSha256.textContent = 'No verified candidate generated';
                restoredContainer.innerHTML = `
                    <div class="preview-placeholder">
                        <p style="font-weight:600;color:var(--color-red);">Forensic Safe Recovery Alert</p>
                        <p style="margin-top:6px;max-width:500px;">
                            Structural damage exists, but no independent recovery reference was available.
                            A complete reconstruction could not be safely produced without fabricating missing bytes.
                        </p>
                    </div>
                `;
            }
        }

        // 6. Forensic Explanation
        const explanationContainer = document.getElementById('explanationContainer');
        explanationContainer.innerHTML = '';
        if (data.explanation && data.explanation.length > 0) {
            data.explanation.forEach(exp => {
                const block = document.createElement('div');
                block.className = 'explanation-block';
                let itemsHtml = '';
                if (exp.items && exp.items.length > 0) {
                    itemsHtml = `<ul>${exp.items.map(it => `<li>${it}</li>`).join('')}</ul>`;
                }
                block.innerHTML = `
                    <h4>${exp.topic}</h4>
                    <p>${exp.detail}</p>
                    ${itemsHtml}
                `;
                explanationContainer.appendChild(block);
            });
        }
    }

    // Run on DOM loaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();