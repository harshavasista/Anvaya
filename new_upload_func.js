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

    const fileSize =
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


    function updateFileDisplay(file) {
        if (!file) {
            dropZone.hidden = false;
            fileSelected.hidden = true;
            analyzeButton.disabled = true;
            if (uploadStatus) {
                uploadStatus.textContent = "Select an evidence file to begin.";
                uploadStatus.className = "upload-status";
            }
            return;
        }

        dropZone.hidden = true;
        fileSelected.hidden = false;
        analyzeButton.disabled = false;

        if (fileName) {
            fileName.textContent = file.name;
        }
        if (fileSize) {
            fileSize.textContent = formatBytes(file.size);
        }
        if (fileIcon) {
            const ext = file.name.split('.').pop().toLowerCase();
            fileIcon.className = `file-icon ${ext}`;
            fileIcon.textContent = getFileIcon(ext);
        }

        if (uploadStatus) {
            uploadStatus.textContent = "File selected. Click Analyze Evidence.";
            uploadStatus.className = "upload-status";
        }
    }

    function getFileIcon(ext) {
        const icons = {
            pdf: "📄",
            docx: "📝",
            xlsx: "📊",
            jpg: "🖼️",
            jpeg: "🖼️",
            png: "🖼️",
            txt: "📃",
            zip: "📦",
            sqlite: "🗃️",
            db: "🗃️"
        };
        return icons[ext] || "📄";
    }

    fileInput.addEventListener(
        "change",
        () => {
            const file = fileInput.files?.[0];
            updateFileDisplay(file);
        }
    );

    // Drag and drop
    dropZone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropZone.classList.add("drag-over");
    });

    dropZone.addEventListener("dragleave", (e) => {
        e.preventDefault();
        dropZone.classList.remove("drag-over");
    });

    dropZone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropZone.classList.remove("drag-over");
        const file = e.dataTransfer.files?.[0];
        if (file) {
            fileInput.files = e.dataTransfer.files;
            updateFileDisplay(file);
        }
    });

    dropZone.addEventListener("click", () => {
        fileInput.click();
    });

    // Remove file
    fileRemove.addEventListener("click", (e) => {
        e.stopPropagation();
        fileInput.value = "";
        updateFileDisplay(null);
    });


    analyzeButton.addEventListener(
        "click",
        async () => {

            const file =
                fileInput.files?.[0];

            if (!file) {

                if (uploadStatus) {
                    uploadStatus.textContent =
                        "Please select an evidence file first.";
                    uploadStatus.className = "upload-status warning";
                }

                return;
            }


            analyzeButton.disabled =
                true;

            const btnText = analyzeButton.querySelector(".btn-text");
            const btnLoader = analyzeButton.querySelector(".btn-loader");

            if (btnText) btnText.textContent = "Analyzing...";
            if (btnLoader) btnLoader.hidden = false;


            if (uploadStatus) {
                uploadStatus.textContent =
                    "Uploading evidence and running forensic analysis...";
                uploadStatus.className = "upload-status";
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
                    uploadStatus.className = "upload-status success";
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
                renderStats(state.stats);
                renderArtifactTable(state.artifacts);
                renderTimeline(state.timeline);
                renderFragmentGraph(state.fragments);

                if (state.fragments.length) {
                    updateFragmentDetails(state.fragments[0].id);
                }

                if (uploadStatus) {
                    uploadStatus.textContent = `Analysis failed: ${error.message}. Showing demo data.`;
                    uploadStatus.className = "upload-status error";
                }

                window.location.hash = "overview";

            } finally {
                analyzeButton.disabled = false;
                if (btnText) btnText.textContent = "Analyze Evidence";
                if (btnLoader) btnLoader.hidden = true;
            }
        }
    );
}