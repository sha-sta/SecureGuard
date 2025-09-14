"use strict";

class EmailScanner {
    constructor() {
        this.provider = null;
        this.currentEmailContainer = null;
        this.scanButton = null;
        this.reportModal = null;
        console.log('veris: Content script loaded on:', window.location.hostname);
        this.detectProvider();
        console.log('veris: Provider detected:', this.provider?.name);
        this.init();
        this.setupMessageListener();
    }

    setupMessageListener() {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            if (request.type === 'MANUAL_SCAN_REQUEST') {
                console.log('veris: Received manual scan request from popup');
                if (this.currentEmailContainer && this.scanButton) {
                    this.scanCurrentEmail();
                    sendResponse({success: true});
                } else {
                    sendResponse({success: false, error: 'No email currently open'});
                }
                return true;
            }
        });
    }

    detectProvider() {
        const hostname = window.location.hostname;
        if (hostname.includes('mail.google.com')) {
            this.provider = {
                name: 'gmail',
                selectors: {
                    emailContainer: '[role="main"] [jsaction*="click"]',
                    openEmailContainer: '[role="main"] [data-message-id], [role="main"] .adn, [role="main"] .ii.gt, .nH .if',
                    fromField: '[email]',
                    toField: '[email]',
                    subjectField: 'h2[data-thread-perm-id]',
                    bodyField: '[dir="ltr"]',
                    attachmentContainer: '[data-tooltip*="attachment"], [data-tooltip*="Attachment"]',
                    linkSelector: 'a[href]:not([href^="mailto:"])',
                    headerContainer: '[role="main"]'
                }
            };
        } else if (hostname.includes('outlook.live.com') || hostname.includes('outlook.office.com')) {
            this.provider = {
                name: 'outlook',
                selectors: {
                    emailContainer: '[role="main"] [data-convid]',
                    openEmailContainer: '[role="main"] [data-convid]',
                    fromField: '[title*="@"]',
                    toField: '[title*="@"]',
                    subjectField: 'div[role="heading"]',
                    bodyField: '[role="document"]',
                    attachmentContainer: '[data-test-id="attachment"]',
                    linkSelector: 'a[href]:not([href^="mailto:"])',
                    headerContainer: '[role="main"]'
                }
            };
        }
    }

    init() {
        if (!this.provider)
            return;
        this.injectStyles();
        this.observeForOpenEmails();
    }

    injectStyles() {
        const style = document.createElement('style');
        style.textContent = `
      @import url('https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@300;400;500;700&display=swap');
      
      .veris-scan-button {
        position: fixed;
        bottom: 40px;
        right: 80px;
        background: linear-gradient(135deg, #4CAF50, #45a049);
        color: white;
        border: none;
        padding: 12px 20px;
        border-radius: 25px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        z-index: 10000;
        box-shadow: 0 4px 12px rgba(76, 175, 80, 0.3);
        transition: all 0.3s ease;
        display: flex;
        align-items: center;
        gap: 8px;
        font-family: 'Roboto Mono', monospace;
      }

      .veris-scan-button:hover {
        background: linear-gradient(135deg, #45a049, #3d8b40);
        transform: translateY(-2px);
        box-shadow: 0 6px 16px rgba(76, 175, 80, 0.4);
      }

      .veris-scan-button:active {
        transform: translateY(0);
      }

      .veris-scan-button.scanning {
        background: linear-gradient(135deg, #ff9800, #f57c00);
        cursor: not-allowed;
      }

      .veris-scan-button .spinner {
        width: 16px;
        height: 16px;
        border: 2px solid #ffffff40;
        border-top: 2px solid #ffffff;
        border-radius: 50%;
        animation: spin 1s linear infinite;
      }

      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }

      .veris-report-modal {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        z-index: 10001;
        display: flex;
        justify-content: center;
        align-items: center;
      }

      .veris-report-content {
        background: white;
        border-radius: 12px;
        padding: 24px;
        max-width: 800px;
        max-height: 80vh;
        overflow-y: auto;
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        position: relative;
        font-family: 'Roboto Mono', monospace;
      }

      .veris-report-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
        padding-bottom: 15px;
        border-bottom: 2px solid #f0f0f0;
      }

      .veris-report-title {
        font-size: 24px;
        font-weight: 700;
        color: #333;
        margin: 0;
        font-family: 'Roboto Mono', monospace;
      }

      .veris-close-button {
        background: #ff4444;
        color: white;
        border: none;
        width: 32px;
        height: 32px;
        border-radius: 50%;
        cursor: pointer;
        font-size: 18px;
        font-weight: bold;
      }

      .veris-overall-score {
        text-align: center;
        margin-bottom: 24px;
        padding: 20px;
        border-radius: 8px;
        font-size: 18px;
        font-weight: 600;
        font-family: 'Roboto Mono', monospace;
      }

      .veris-overall-score.high {
        background: rgba(255, 68, 68, 0.1);
        color: #cc0000;
        border: 2px solid #ff4444;
      }

      .veris-overall-score.medium {
        background: rgba(255, 136, 0, 0.1);
        color: #e67300;
        border: 2px solid #ff8800;
      }

      .veris-overall-score.low {
        background: rgba(76, 175, 80, 0.1);
        color: #2e7d32;
        border: 2px solid #4CAF50;
      }

      .veris-category-scores {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
      }

      .veris-category-score {
        background: #f8f9fa;
        padding: 16px;
        border-radius: 8px;
        text-align: center;
        border: 2px solid #e9ecef;
      }

      .veris-category-score.high {
        border-color: #ff4444;
        background: #fff5f5;
      }

      .veris-category-score.medium {
        border-color: #ff8800;
        background: #fff8f0;
      }

      .veris-category-score.low {
        border-color: #4CAF50;
        background: #f8fff8;
      }

      .veris-category-score.na {
        opacity: 0.5;
        border-color: #ccc;
        background: #f5f5f5;
      }

      .veris-category-title {
        font-weight: 600;
        font-size: 14px;
        color: #666;
        text-transform: uppercase;
        margin-bottom: 8px;
        font-family: 'Roboto Mono', monospace;
      }

      .veris-progress-container {
        position: relative;
        width: 100px;
        height: 50px;
        margin: 15px auto;
      }

      .veris-progress-svg {
        width: 100px;
        height: 50px;
        transform: rotate(0deg);
      }

      .veris-progress-bg {
        fill: none;
        stroke: #e9ecef;
        stroke-width: 6;
        stroke-linecap: round;
      }

      .veris-progress-bar {
        fill: none;
        stroke-width: 6;
        stroke-linecap: round;
        transition: stroke-dashoffset 1.5s ease-in-out;
      }

      .veris-progress-bar.high {
        stroke: #ff4444;
      }

      .veris-progress-bar.medium {
        stroke: #ff8800;
      }

      .veris-progress-bar.low {
        stroke: #4CAF50;
      }

      .veris-progress-bar.na {
        stroke: #ccc;
      }

      .veris-progress-text {
        position: absolute;
        bottom: -5px;
        left: 50%;
        transform: translateX(-50%);
        font-weight: 600;
        font-size: 14px;
        color: #333;
        font-family: 'Roboto Mono', monospace;
      }

      .veris-category-value {
        font-size: 24px;
        font-weight: 700;
        color: #333;
        font-family: 'Roboto Mono', monospace;
      }

      .veris-gemini-section {
        margin-bottom: 24px;
        padding: 20px;
        background: #f0f8ff;
        border-radius: 8px;
        border-left: 4px solid #2196F3;
      }

      .veris-gemini-title {
        font-size: 18px;
        font-weight: 600;
        color: #1976D2;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .veris-gemini-reasoning {
        color: #333;
        line-height: 1.6;
      }

      .veris-factors-title {
        font-size: 18px;
        font-weight: 600;
        color: #cc0000;
        margin-bottom: 12px;
        margin-top: 0;
      }

      .veris-suspicious-highlight {
        background-color: rgba(255, 0, 0, 0.2);
        border-bottom: 2px solid #ff0000;
        cursor: help;
        position: relative;
      }

      .veris-highlight-tooltip {
        position: absolute;
        background: #333;
        color: white;
        padding: 8px 12px;
        border-radius: 4px;
        font-size: 12px;
        z-index: 10002;
        max-width: 250px;
        bottom: 100%;
        left: 50%;
        transform: translateX(-50%);
        margin-bottom: 5px;
        opacity: 0;
        pointer-events: none;
        transition: opacity 0.2s;
      }

      .veris-suspicious-highlight:hover .veris-highlight-tooltip {
        opacity: 1;
      }

      .veris-factors-list {
        margin-bottom: 24px;
        padding: 20px;
        background: #fff5f5;
        border-radius: 8px;
        border-left: 4px solid #ff4444;
      }

      .veris-factor-item {
        padding: 8px 0;
        border-bottom: 1px solid #e9ecef;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }

      .veris-factor-item:last-child {
        border-bottom: none;
      }

      .veris-factor-risk {
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
      }

      .veris-factor-risk.high {
        background: #ff4444;
        color: white;
      }

      .veris-factor-risk.medium {
        background: #ff8800;
        color: white;
      }

      .veris-factor-risk.low {
        background: #4CAF50;
        color: white;
      }
    `;
        document.head.appendChild(style);
    }

    observeForOpenEmails() {
        const observer = new MutationObserver(() => {
            this.checkForOpenEmail();
        });
        observer.observe(document.body, {childList: true, subtree: true});
        observer.observe(document.body, {childList: true, subtree: true});
        let currentUrl = window.location.href;
        setInterval(() => {
            if (window.location.href !== currentUrl) {
                currentUrl = window.location.href;
                setTimeout(() => this.checkForOpenEmail(), 500);
            }
        }, 1000);
        setTimeout(() => this.checkForOpenEmail(), 1000);
    }

    checkForOpenEmail() {
        const emailContainer = document.querySelector(this.provider.selectors.openEmailContainer);
        console.log('veris: Checking for open email. Found container:', !!emailContainer);
        if (emailContainer && emailContainer !== this.currentEmailContainer) {
            console.log('veris: New email detected, showing scan button');
            this.currentEmailContainer = emailContainer;
            this.showScanButton();
        } else if (!emailContainer && this.currentEmailContainer) {
            console.log('veris: Email closed, hiding scan button');
            this.currentEmailContainer = null;
            this.hideScanButton();
            this.hideReport();
        }
    }

    showScanButton() {
        console.log('veris: Creating and showing scan button');
        if (this.scanButton) {
            this.scanButton.remove();
        }
        this.scanButton = document.createElement('button');
        this.scanButton.className = 'veris-scan-button';
        this.scanButton.innerHTML = `
      <span>Scan Email</span>
    `;
        this.scanButton.addEventListener('click', () => this.scanCurrentEmail());
        document.body.appendChild(this.scanButton);
    }

    hideScanButton() {
        if (this.scanButton) {
            this.scanButton.remove();
            this.scanButton = null;
        }
    }

    async scanCurrentEmail() {

        console.log('SecureGuard: Starting email scan...');
        if (!this.currentEmailContainer || !this.scanButton) {
            console.error('SecureGuard: Missing email container or scan button');
            return;
        }
        try {
            const payload = {
                url: location.href,
                timestamp: new Date().toISOString(),
                html: document.documentElement.outerHTML
            };
            console.log('SecureGuard: Sending HTML for analysis...');
            const analysisResponse = await fetch('http://localhost:8000/analyze-email-from-html', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });
            if (!analysisResponse.ok) {
                throw new Error(`Analysis failed: HTTP ${analysisResponse.status}`);
            }
            const analysisResult = await analysisResponse.json();
            console.log('SecureGuard: Analysis result:', analysisResult);
            if (analysisResult.success) {
                const detailedResult = {
                    success: true,
                    riskScore: analysisResult.riskScore,
                    categoryScores: this.calculateCategoryScores(analysisResult.riskScore.factors),
                    geminiReasoning: this.extractGeminiReasoning(analysisResult.riskScore.factors),
                    suspiciousTextRanges: []
                };
                this.showDetailedReport(detailedResult);
                this.highlightSuspiciousContent(detailedResult);
                return;
            } else {
                throw new Error(analysisResult.error || 'Analysis failed');
            }
        } catch (htmlAnalysisError) {
            console.error('SecureGuard: HTML analysis failed, falling back to DOM extraction:', htmlAnalysisError);
        }
        this.scanButton.innerHTML = `
      <div class="spinner"></div>
      <span>Scanning...</span>
    `;
        this.scanButton.classList.add('scanning');
        this.scanButton.disabled = true;
        try {
            console.log('veris: Extracting email data...');
            const emailData = await this.extractEmailData(this.currentEmailContainer);
            console.log('veris: Email data extracted:', emailData);
            console.log('veris: Sending message to background script...');
            const response = await chrome.runtime.sendMessage({
                type: 'ANALYZE_EMAIL_DETAILED',
                emailData
            });
            console.log('veris: Background script response:', response);
            if (response && response.success) {
                console.log('veris: Analysis successful, showing report...');
                this.showDetailedReport(response);
                this.highlightSuspiciousContent(response);
            } else {
                console.error('veris: Analysis failed:', response);
                this.showError(response?.error || 'Analysis failed');
            }
        } catch (error) {
            console.error('veris: Error scanning email:', error);
            this.showError(`Failed to scan email: ${error instanceof Error ? error.message : String(error)}`);
        } finally {
            this.scanButton.innerHTML = `
        <span>Scan Email</span>
      `;
            this.scanButton.classList.remove('scanning');
            this.scanButton.disabled = false;
        }

    }

    async extractEmailData(container) {
        const fromElement = container.querySelector(this.provider.selectors.fromField);
        const subjectElement = container.querySelector(this.provider.selectors.subjectField);
        const bodyElement = container.querySelector(this.provider.selectors.bodyField);
        const headers = this.extractHeaders(container);
        const emailData = {
            from: fromElement?.textContent?.trim() || fromElement?.getAttribute('email') || '',
            to: this.extractRecipients(container),
            subject: subjectElement?.textContent?.trim() || '',
            body: bodyElement?.textContent?.trim() || '',
            headers: headers,
            links: this.extractLinks(container),
            attachments: await this.extractAttachments(container),
            timestamp: new Date().toISOString(),
            messageId: container.getAttribute('data-message-id') ||
                container.getAttribute('data-convid') ||
                Math.random().toString(36)
        };
        return emailData;
    }

    extractHeaders(container) {
        const headers = {};
        const fromElement = container.querySelector('[email]');
        if (fromElement) {
            headers['From'] = fromElement.getAttribute('email') || fromElement.textContent?.trim() || '';
        }
        const dateElement = container.querySelector('[data-tooltip*="GMT"], [title*="GMT"]');
        if (dateElement) {
            headers['Date'] = dateElement.getAttribute('data-tooltip') || dateElement.getAttribute('title') || '';
        }
        const messageId = container.getAttribute('data-message-id');
        if (messageId) {
            headers['Message-ID'] = messageId;
        }
        return headers;
    }

    extractRecipients(container) {
        const recipients = [];
        const toElements = container.querySelectorAll('[email]');
        toElements.forEach(element => {
            const email = element.getAttribute('email') || element.textContent?.trim();
            if (email && !recipients.includes(email)) {
                recipients.push(email);
            }
        });
        if (recipients.length === 0) {
            recipients.push('user@example.com');
        }
        console.log('veris: Extracted recipients:', recipients);
        return recipients;
    }

    extractLinks(container) {
        const links = container.querySelectorAll(this.provider.selectors.linkSelector);
        const linkData = [];
        links.forEach((link, index) => {
            const href = link.getAttribute('href');
            if (href && !href.startsWith('mailto:') && !href.startsWith('#')) {
                linkData.push({
                    url: href,
                    displayText: link.textContent?.trim() || '',
                    position: index
                });
            }
        });
        return linkData;
    }

    async extractAttachments(container) {
        const attachments = container.querySelectorAll(this.provider.selectors.attachmentContainer);
        const attachmentData = [];
        for (let i = 0; i < attachments.length; i++) {
            const attachment = attachments[i];
            const filename = attachment.textContent?.trim() ||
                attachment.getAttribute('data-tooltip') ||
                attachment.getAttribute('aria-label') ||
                'unknown';
            let size = 0;
            let hash;
            const sizeText = attachment.getAttribute('data-size') ||
                attachment.querySelector('[data-size]')?.getAttribute('data-size') ||
                '';
            if (sizeText) {
                size = parseInt(sizeText) || 0;
            }
            const hashAttr = attachment.getAttribute('data-hash') ||
                attachment.querySelector('[data-hash]')?.getAttribute('data-hash');
            if (hashAttr) {
                hash = hashAttr;
            }
            let mimeType = 'application/octet-stream';
            const fileExtension = filename.split('.').pop()?.toLowerCase();
            if (fileExtension) {
                mimeType = this.getMimeTypeFromExtension(fileExtension);
            }
            attachmentData.push({
                filename,
                mimeType,
                size,
                hash
            });
        }
        return attachmentData;
    }

    getMimeTypeFromExtension(extension) {
        const mimeTypes = {
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xls': 'application/vnd.ms-excel',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'ppt': 'application/vnd.ms-powerpoint',
            'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'txt': 'text/plain',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'zip': 'application/zip',
            'rar': 'application/x-rar-compressed',
            'exe': 'application/x-msdownload',
            'js': 'text/javascript',
            'html': 'text/html',
            'css': 'text/css'
        };
        return mimeTypes[extension] || 'application/octet-stream';
    }

    calculateCategoryScores(factors) {
        const categories = {
            header: [],
            content: [],
            links: [],
            attachments: []
        };
        factors.forEach(factor => {
            const category = factor.category.toLowerCase();
            if (categories[category]) {
                categories[category].push(factor.score);
            }
        });
        return {
            header: categories.header.length > 0 ? Math.max(...categories.header) : null,
            content: categories.content.length > 0 ? Math.max(...categories.content) : null,
            links: categories.links.length > 0 ? Math.max(...categories.links) : null,
            attachments: categories.attachments.length > 0 ? Math.max(...categories.attachments) : null
        };
    }

    extractGeminiReasoning(factors) {
        const aiFactors = factors.filter(factor => factor.description.includes('AI Analysis:') ||
            factor.description.includes('Gemini'));
        if (aiFactors.length > 0) {
            return aiFactors.map(factor => factor.description.replace('AI Analysis: ', '')).join(' ');
        }
        return 'No AI analysis available for this email.';
    }

    showDetailedReport(result) {
        this.hideReport();
        this.reportModal = document.createElement('div');
        this.reportModal.className = 'veris-report-modal';
        const overallRisk = result.riskScore.overall.toLowerCase();
        const overallIcon = result.riskScore.overall === 'HIGH' ? '⚠️' :
            result.riskScore.overall === 'MEDIUM' ? '⚡' : '✅';
        this.reportModal.innerHTML = `
      <div class="veris-report-content">
        <div class="veris-report-header">
          <h2 class="veris-report-title">Email Security Report</h2>
          <button class="veris-close-button">×</button>
        </div>

        <div class="veris-overall-score ${overallRisk}">
          <div>Overall Risk: ${result.riskScore.overall} ${overallIcon}</div>
          ${this.generateProgressBar(result.riskScore.score, overallRisk)}
        </div>

        <div class="veris-category-scores">
          <div class="veris-category-score ${this.getRiskClass(result.categoryScores.header)}">
            <div class="veris-category-title">Headers</div>
            ${this.generateProgressBar(result.categoryScores.header, this.getRiskClass(result.categoryScores.header))}
          </div>
          <div class="veris-category-score ${this.getRiskClass(result.categoryScores.content)}">
            <div class="veris-category-title">Content</div>
            ${this.generateProgressBar(result.categoryScores.content, this.getRiskClass(result.categoryScores.content))}
          </div>
          <div class="veris-category-score ${this.getRiskClass(result.categoryScores.links)}">
            <div class="veris-category-title">Links</div>
            ${this.generateProgressBar(result.categoryScores.links, this.getRiskClass(result.categoryScores.links))}
          </div>
          <div class="veris-category-score ${this.getRiskClass(result.categoryScores.attachments)}">
            <div class="veris-category-title">Attachments</div>
            ${this.generateProgressBar(result.categoryScores.attachments, this.getRiskClass(result.categoryScores.attachments))}
          </div>
        </div>

        ${result.geminiReasoning ? `
        <div class="veris-gemini-section">
          <div class="veris-gemini-title">
            <span>AI Analysis</span>
          </div>
          <div class="veris-gemini-reasoning">${result.riskScore.factors[result.riskScore.factors.length-1].description}</div>
        </div>
        ` : ''}
        

        <div class="veris-factors-list">
          <h3 class="veris-factors-title">Risk Factors</h3>
          ${result.riskScore.factors.map(factor => `
            <div class="veris-factor-item">
              <div>
                <strong>${factor.category}:</strong> ${factor.description}
                ${factor.details ? `<br><small style="color: #666;">${factor.details}</small>` : ''}
              </div>
              <span class="veris-factor-risk ${factor.risk.toLowerCase()}">${factor.risk}</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
        const closeButton = this.reportModal.querySelector('.veris-close-button');
        closeButton?.addEventListener('click', () => this.hideReport());
        this.reportModal.addEventListener('click', (e) => {
            if (e.target === this.reportModal) {
                this.hideReport();
            }
        });
        document.body.appendChild(this.reportModal);
    }

    getRiskClass(score) {
        if (score === null)
            return 'na';
        if (score >= 70)
            return 'high';
        if (score >= 40)
            return 'medium';
        return 'low';
    }

    generateProgressBar(score, riskClass) {
        if (score === null) {
            return `
        <div class="veris-progress-container">
          <svg class="veris-progress-svg" viewBox="0 0 100 50">
            <path class="veris-progress-bg" 
                  d="M 15,45 A 35,35 0 1,1 85,45"
                  stroke-dasharray="110"
                  stroke-dashoffset="0"></path>
          </svg>
          <div class="veris-progress-text">N/A</div>
        </div>
      `;
        }
        const pathLength = 110;
        const offset = pathLength - (score / 100) * pathLength;
        return `
      <div class="veris-progress-container">
        <svg class="veris-progress-svg" viewBox="0 0 100 50">
          <path class="veris-progress-bg" 
                d="M 15,45 A 35,35 0 1,1 85,45"
                stroke-dasharray="${pathLength}"
                stroke-dashoffset="0"></path>
          <path class="veris-progress-bar ${riskClass}" 
                d="M 15,45 A 35,35 0 1,1 85,45"
                stroke-dasharray="${pathLength}"
                stroke-dashoffset="${offset}"></path>
        </svg>
        <div class="veris-progress-text">${score}%</div>
      </div>
    `;
    }

    highlightSuspiciousContent(result) {
        if (!result.suspiciousTextRanges || !this.currentEmailContainer)
            return;
        const bodyElement = this.currentEmailContainer.querySelector(this.provider.selectors.bodyField);
        if (!bodyElement)
            return;
        const textContent = bodyElement.textContent || '';
        const highlights = result.suspiciousTextRanges
            .filter(range => range.startIndex < textContent.length)
            .sort((a, b) => b.startIndex - a.startIndex);
        highlights.forEach(highlight => {
            this.highlightTextInElement(bodyElement, highlight.text, highlight.reason);
        });
    }

    highlightTextInElement(element, searchText, reason) {
        const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null);
        const textNodes = [];
        let node;
        while (node = walker.nextNode()) {
            textNodes.push(node);
        }
        textNodes.forEach(textNode => {
            const text = textNode.textContent || '';
            const index = text.toLowerCase().indexOf(searchText.toLowerCase());
            if (index !== -1) {
                const beforeText = text.substring(0, index);
                const matchText = text.substring(index, index + searchText.length);
                const afterText = text.substring(index + searchText.length);
                const fragment = document.createDocumentFragment();
                if (beforeText) {
                    fragment.appendChild(document.createTextNode(beforeText));
                }
                const highlight = document.createElement('span');
                highlight.className = 'veris-suspicious-highlight';
                highlight.textContent = matchText;
                const tooltip = document.createElement('div');
                tooltip.className = 'veris-highlight-tooltip';
                tooltip.textContent = reason;
                highlight.appendChild(tooltip);
                fragment.appendChild(highlight);
                if (afterText) {
                    fragment.appendChild(document.createTextNode(afterText));
                }
                textNode.parentNode?.replaceChild(fragment, textNode);
            }
        });
    }

    hideReport() {
        if (this.reportModal) {
            this.reportModal.remove();
            this.reportModal = null;
        }
    }

    showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #ff4444;
      color: white;
      padding: 16px 20px;
      border-radius: 8px;
      z-index: 10001;
      max-width: 300px;
    `;
        errorDiv.textContent = `veris Error: ${message}`;
        document.body.appendChild(errorDiv);
        setTimeout(() => {
            errorDiv.remove();
        }, 5000);
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new EmailScanner());
} else {
    new EmailScanner();
}
//# sourceMappingURL=content.js.map