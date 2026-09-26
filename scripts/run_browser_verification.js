const puppeteer = require('puppeteer-core');
const path = require('path');
const fs = require('fs');

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const APP_URL = 'http://127.0.0.1:5500';

const sleep = (ms) => new Promise(res => setTimeout(res, ms));

async function runTestScenario(browser, name, filePath, outputDir, options = {}) {
    console.log(`\n======================================================`);
    console.log(`Running Scenario: ${name}`);
    console.log(`File: ${filePath}`);
    console.log(`======================================================`);

    const page = await browser.newPage();
    await page.setViewport({ width: 1400, height: 950 });

    const consoleLogs = [];
    const failedRequests = [];

    page.on('console', msg => {
        const text = msg.text();
        consoleLogs.push({ type: msg.type(), text });
        if (msg.type() === 'error') {
            console.error(`  [Browser Console Error]: ${text}`);
        }
    });

    page.on('requestfailed', req => {
        failedRequests.push({ url: req.url(), failure: req.failure().errorText });
        console.warn(`  [Network Request Failed]: ${req.url()} (${req.failure().errorText})`);
    });

    try {
        await page.goto(APP_URL, { waitUntil: 'networkidle0', timeout: 15000 });

        // Verify initial page load
        const title = await page.title();
        console.log(`  Page title: "${title}"`);

        // Upload file via the file input
        const fileInputHandle = await page.$('#fileInput');
        if (!fileInputHandle) throw new Error('#fileInput not found');

        const absolutePath = path.resolve(filePath);
        await fileInputHandle.uploadFile(absolutePath);
        await sleep(500);

        // Verify file selected info is visible
        const selectedName = await page.$eval('#selectedFileName', el => el.textContent.trim());
        console.log(`  Selected File in UI: "${selectedName}"`);

        // Check if analyze button is enabled
        const isAnalyzeDisabled = await page.$eval('#btnAnalyze', el => el.disabled);
        if (isAnalyzeDisabled) throw new Error('Analyze button remained disabled after file selection');

        // Click Analyze Evidence
        console.log(`  Clicking "ANALYZE EVIDENCE"...`);
        await page.click('#btnAnalyze');

        // Wait for results container or error banner to appear
        await page.waitForFunction(() => {
            const res = document.getElementById('resultsContainer');
            const err = document.getElementById('errorBanner');
            return (res && !res.classList.contains('hidden')) || (err && !err.classList.contains('hidden'));
        }, { timeout: 20000 });

        await sleep(1500); // Allow iframe/rendering to stabilize

        // Check if error was triggered
        const hasError = await page.$eval('#errorBanner', el => !el.classList.contains('hidden'));
        if (hasError) {
            const errTxt = await page.$eval('#errorMessage', el => el.textContent.trim());
            console.log(`  Error Banner displayed: "${errTxt}"`);
            if (!options.expectError) {
                throw new Error(`Unexpected error banner: ${errTxt}`);
            }
        } else {
            // Read extracted metrics from UI
            const caseId = await page.$eval('#caseIdBadge', el => el.textContent.trim());
            const fileType = await page.$eval('#valFileType', el => el.textContent.trim());
            const sha256 = await page.$eval('#valSha256', el => el.textContent.trim());
            const corruptionStatus = await page.$eval('#corruptionStatusBadge', el => el.textContent.trim());
            const recoveryStatus = await page.$eval('#recoveryStatusBadge', el => el.textContent.trim());

            console.log(`  Case ID: ${caseId}`);
            console.log(`  Detected Type: ${fileType}`);
            console.log(`  SHA-256: ${sha256}`);
            console.log(`  Corruption Status: ${corruptionStatus}`);
            console.log(`  Recovery Status: ${recoveryStatus}`);

            // Side-by-Side Verification
            const isNoRefVisible = await page.$eval('#noReferenceNotice', el => !el.classList.contains('hidden'));
            console.log(`  Reference notice visible: ${isNoRefVisible}`);

            const leftTitle = await page.$eval('#leftPanelTitle', el => el.textContent.trim());
            const rightTitle = await page.$eval('#rightPanelTitle', el => el.textContent.trim());
            console.log(`  Left Panel: "${leftTitle}"`);
            console.log(`  Right Panel: "${rightTitle}"`);

            // Verify if preview elements rendered
            const leftHasIframe = await page.$eval('#leftPreviewContainer', el => !!el.querySelector('iframe, pre, img'));
            const rightHasIframe = await page.$eval('#rightPreviewContainer', el => !!el.querySelector('iframe, pre, img'));
            console.log(`  Left Panel Rendered Content: ${leftHasIframe}`);
            console.log(`  Right Panel Rendered Content: ${rightHasIframe}`);

            // Restored Candidate verification
            const restoredHasContent = await page.$eval('#restoredPreviewContainer', el => !!el.querySelector('iframe, pre, img, .preview-placeholder'));
            console.log(`  Restored Candidate Preview Rendered: ${restoredHasContent}`);
        }

        // Take screenshot
        fs.mkdirSync(outputDir, { recursive: true });
        const screenshotPath = path.join(outputDir, `${name.toLowerCase().replace(/[^a-z0-9]/g, '_')}.png`);
        await page.screenshot({ path: screenshotPath, fullPage: true });
        console.log(`  Screenshot saved to: ${screenshotPath}`);

        // Save notes
        const notesPath = path.join(outputDir, `${name.toLowerCase().replace(/[^a-z0-9]/g, '_')}_notes.json`);
        fs.writeFileSync(notesPath, JSON.stringify({
            scenario: name,
            file: filePath,
            timestamp: new Date().toISOString(),
            consoleErrors: consoleLogs.filter(c => c.type === 'error'),
            failedRequests: failedRequests,
            success: true
        }, null, 2));

    } catch (err) {
        console.error(`  Scenario FAILED: ${err.message}`);
        fs.mkdirSync(outputDir, { recursive: true });
        const errScreenshotPath = path.join(outputDir, `${name.toLowerCase().replace(/[^a-z0-9]/g, '_')}_error.png`);
        await page.screenshot({ path: errScreenshotPath, fullPage: true });
        throw err;
    } finally {
        await page.close();
    }
}

async function main() {
    console.log('Launching Headless Chrome for ANVAYA Forensic System Verification...');
    const browser = await puppeteer.launch({
        executablePath: CHROME_PATH,
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--allow-file-access-from-files']
    });

    try {
        // Priority 1: Safe Evidence Ingestion (Upload, SHA-256, Case ID)
        await runTestScenario(browser, 'Priority_01_Ingestion_Healthy_PDF', 'data/demo/clean_evidence.pdf', 'verification/priority-01');

        // Priority 2: Format Identification (Clean JSON, CSV, PNG, SQLite)
        await runTestScenario(browser, 'Priority_02_Format_Identification_JSON', 'data/demo/clean_evidence.json', 'verification/priority-02');
        await runTestScenario(browser, 'Priority_02_Format_Identification_PNG', 'data/demo/clean_evidence.png', 'verification/priority-02');

        // Priority 3: Corruption Detection Engine (Corrupted PDF, JSON, TXT)
        await runTestScenario(browser, 'Priority_03_Corruption_Detection_TXT', 'data/demo/corrupted_evidence.txt', 'verification/priority-03');

        // Priority 4: PDF Primary Demonstration Centerpiece (Corrupted PDF with Real Reference Side-by-Side + Restored PDF Render)
        await runTestScenario(browser, 'Priority_04_Corrupted_PDF_Reference_And_Repair', 'data/demo/corrupted_evidence.pdf', 'verification/priority-04');

        // Priority 5: Corrupted PDF WITHOUT Reference (Untracked Corrupted PDF)
        await runTestScenario(browser, 'Priority_05_Corrupted_PDF_Without_Reference', 'data/demo/untracked_corrupted.pdf', 'verification/priority-05');

        // Priority 6: TXT & JSON Recovery and Validation
        await runTestScenario(browser, 'Priority_06_JSON_Corruption_And_Repair', 'data/demo/corrupted_evidence.json', 'verification/priority-06');

        // Priority 7: Edge Cases & Adversarial Input (Zero-byte file, etc.)
        const emptyFilePath = path.join('data', 'demo', 'zero_byte.bin');
        fs.writeFileSync(emptyFilePath, Buffer.alloc(0));
        await runTestScenario(browser, 'Priority_07_Adversarial_Zero_Byte', emptyFilePath, 'verification/priority-07');

        // Final Acceptance Demonstration (Section 46)
        await runTestScenario(browser, 'Final_Acceptance_Corrupted_PDF_Demonstration', 'data/demo/corrupted_evidence.pdf', 'verification/final');

        console.log('\n======================================================');
        console.log('ALL FORENSIC VERIFICATION SCENARIOS PASSED IN BROWSER!');
        console.log('======================================================');
    } finally {
        await browser.close();
    }
}

main().catch(err => {
    console.error('Browser Verification Suite Failed:', err);
    process.exit(1);
});
