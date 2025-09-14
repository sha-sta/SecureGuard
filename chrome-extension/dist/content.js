"use strict";
class EmailScanner {
    constructor() {
        this.provider = null;
        this.currentEmailContainer = null;
        this.scanButton = null;
        this.reportModal = null;
        console.log('SecureGuard: Content script loaded on:', window.location.hostname);
        this.detectProvider();
        console.log('SecureGuard: Provider detected:', this.provider?.name);
        this.init();
        this.setupMessageListener();
    }
    setupMessageListener() {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            if (request.type === 'MANUAL_SCAN_REQUEST') {
                console.log('SecureGuard: Received manual scan request from popup');
                if (this.currentEmailContainer && this.scanButton) {
                    this.scanCurrentEmail();
                    sendResponse({ success: true });
                }
                else {
                    sendResponse({ success: false, error: 'No email currently open' });
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
        }
        else if (hostname.includes('outlook.live.com') || hostname.includes('outlook.office.com')) {
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
      .secureguard-scan-button {
        position: fixed;
        top: 20px;
        right: 20px;
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
      }

      .secureguard-scan-button:hover {
        background: linear-gradient(135deg, #45a049, #3d8b40);
        transform: translateY(-2px);
        box-shadow: 0 6px 16px rgba(76, 175, 80, 0.4);
      }

      .secureguard-scan-button:active {
        transform: translateY(0);
      }

      .secureguard-scan-button.scanning {
        background: linear-gradient(135deg, #ff9800, #f57c00);
        cursor: not-allowed;
      }

      .secureguard-scan-button .spinner {
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

      .secureguard-report-modal {
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

      .secureguard-report-content {
        background: white;
        border-radius: 12px;
        padding: 24px;
        max-width: 800px;
        max-height: 80vh;
        overflow-y: auto;
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        position: relative;
      }

      .secureguard-report-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
        padding-bottom: 15px;
        border-bottom: 2px solid #f0f0f0;
      }

      .secureguard-report-title {
        font-size: 24px;
        font-weight: 700;
        color: #333;
        margin: 0;
      }

      .secureguard-close-button {
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

      .secureguard-overall-score {
        text-align: center;
        margin-bottom: 24px;
        padding: 20px;
        border-radius: 8px;
        font-size: 18px;
        font-weight: 600;
      }

      .secureguard-overall-score.high {
        background: linear-gradient(135deg, #ff4444, #cc0000);
        color: white;
      }

      .secureguard-overall-score.medium {
        background: linear-gradient(135deg, #ff8800, #e67300);
        color: white;
      }

      .secureguard-overall-score.low {
        background: linear-gradient(135deg, #4CAF50, #45a049);
        color: white;
      }

      .secureguard-category-scores {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
      }

      .secureguard-category-score {
        background: #f8f9fa;
        padding: 16px;
        border-radius: 8px;
        text-align: center;
        border: 2px solid #e9ecef;
      }

      .secureguard-category-score.high {
        border-color: #ff4444;
        background: #fff5f5;
      }

      .secureguard-category-score.medium {
        border-color: #ff8800;
        background: #fff8f0;
      }

      .secureguard-category-score.low {
        border-color: #4CAF50;
        background: #f8fff8;
      }

      .secureguard-category-score.na {
        opacity: 0.5;
        border-color: #ccc;
        background: #f5f5f5;
      }

      .secureguard-category-title {
        font-weight: 600;
        font-size: 14px;
        color: #666;
        text-transform: uppercase;
        margin-bottom: 8px;
      }

      .secureguard-category-value {
        font-size: 24px;
        font-weight: 700;
        color: #333;
      }

      .secureguard-gemini-section {
        margin-bottom: 24px;
        padding: 20px;
        background: #f0f8ff;
        border-radius: 8px;
        border-left: 4px solid #2196F3;
      }

      .secureguard-gemini-title {
        font-size: 18px;
        font-weight: 600;
        color: #1976D2;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .secureguard-gemini-reasoning {
        color: #333;
        line-height: 1.6;
      }

      .secureguard-suspicious-highlight {
        background-color: rgba(255, 0, 0, 0.2);
        border-bottom: 2px solid #ff0000;
        cursor: help;
        position: relative;
      }

      .secureguard-highlight-tooltip {
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

      .secureguard-suspicious-highlight:hover .secureguard-highlight-tooltip {
        opacity: 1;
      }

      .secureguard-factors-list {
        background: #f8f9fa;
        padding: 16px;
        border-radius: 8px;
        margin-top: 16px;
      }

      .secureguard-factor-item {
        padding: 8px 0;
        border-bottom: 1px solid #e9ecef;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }

      .secureguard-factor-item:last-child {
        border-bottom: none;
      }

      .secureguard-factor-risk {
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
      }

      .secureguard-factor-risk.high {
        background: #ff4444;
        color: white;
      }

      .secureguard-factor-risk.medium {
        background: #ff8800;
        color: white;
      }

      .secureguard-factor-risk.low {
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
        observer.observe(document.body, { childList: true, subtree: true });
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
        console.log('SecureGuard: Checking for open email. Found container:', !!emailContainer);
        if (emailContainer && emailContainer !== this.currentEmailContainer) {
            console.log('SecureGuard: New email detected, showing scan button');
            this.currentEmailContainer = emailContainer;
            this.showScanButton();
        }
        else if (!emailContainer && this.currentEmailContainer) {
            console.log('SecureGuard: Email closed, hiding scan button');
            this.currentEmailContainer = null;
            this.hideScanButton();
            this.hideReport();
        }
    }
    showScanButton() {
        console.log('SecureGuard: Creating and showing scan button');
        if (this.scanButton) {
            this.scanButton.remove();
        }
        this.scanButton = document.createElement('button');
        this.scanButton.className = 'secureguard-scan-button';
        this.scanButton.innerHTML = `
      <span>🛡️</span>
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
                headers: { 'Content-Type': 'application/json' },
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
            }
            else {
                throw new Error(analysisResult.error || 'Analysis failed');
            }
        }
        catch (htmlAnalysisError) {
            console.error('SecureGuard: HTML analysis failed, falling back to DOM extraction:', htmlAnalysisError);
        }
        this.scanButton.innerHTML = `
      <div class="spinner"></div>
      <span>Scanning...</span>
    `;
        this.scanButton.classList.add('scanning');
        this.scanButton.disabled = true;
        try {
            console.log('SecureGuard: Extracting email data...');
            const emailData = await this.extractEmailData(this.currentEmailContainer);
            console.log('SecureGuard: Email data extracted:', emailData);
            console.log('SecureGuard: Sending message to background script...');
            const response = await chrome.runtime.sendMessage({
                type: 'ANALYZE_EMAIL_DETAILED',
                emailData
            });
            console.log('SecureGuard: Background script response:', response);
            if (response && response.success) {
                console.log('SecureGuard: Analysis successful, showing report...');
                this.showDetailedReport(response);
                this.highlightSuspiciousContent(response);
            }
            else {
                console.error('SecureGuard: Analysis failed:', response);
                this.showError(response?.error || 'Analysis failed');
            }
        }
        catch (error) {
            console.error('SecureGuard: Error scanning email:', error);
            this.showError(`Failed to scan email: ${error instanceof Error ? error.message : String(error)}`);
        }
        finally {
            this.scanButton.innerHTML = `
        <span>🛡️</span>
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
        console.log('SecureGuard: Extracted recipients:', recipients);
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
        this.reportModal.className = 'secureguard-report-modal';
        const overallRisk = result.riskScore.overall.toLowerCase();
        const overallIcon = result.riskScore.overall === 'HIGH' ? '⚠️' :
            result.riskScore.overall === 'MEDIUM' ? '⚡' : '✅';
        this.reportModal.innerHTML = `
      <div class="secureguard-report-content">
        <div class="secureguard-report-header">
          <h2 class="secureguard-report-title">🛡️ Email Security Report</h2>
          <button class="secureguard-close-button">×</button>
        </div>

        <div class="secureguard-overall-score ${overallRisk}">
          <div>${overallIcon} Overall Risk: ${result.riskScore.overall}</div>
          <div>Score: ${result.riskScore.score}/100</div>
        </div>

        <div class="secureguard-category-scores">
          <div class="secureguard-category-score ${this.getRiskClass(result.categoryScores.header)}">
            <div class="secureguard-category-title">Headers</div>
            <div class="secureguard-category-value">${result.categoryScores.header !== null ? result.categoryScores.header + '/100' : 'N/A'}</div>
          </div>
          <div class="secureguard-category-score ${this.getRiskClass(result.categoryScores.content)}">
            <div class="secureguard-category-title">Content</div>
            <div class="secureguard-category-value">${result.categoryScores.content !== null ? result.categoryScores.content + '/100' : 'N/A'}</div>
          </div>
          <div class="secureguard-category-score ${this.getRiskClass(result.categoryScores.links)}">
            <div class="secureguard-category-title">Links</div>
            <div class="secureguard-category-value">${result.categoryScores.links !== null ? result.categoryScores.links + '/100' : 'N/A'}</div>
          </div>
          <div class="secureguard-category-score ${this.getRiskClass(result.categoryScores.attachments)}">
            <div class="secureguard-category-title">Attachments</div>
            <div class="secureguard-category-value">${result.categoryScores.attachments !== null ? result.categoryScores.attachments + '/100' : 'N/A'}</div>
          </div>
        </div>

        ${result.geminiReasoning ? `
        <div class="secureguard-gemini-section">
          <div class="secureguard-gemini-title">
            <span>🤖</span>
            <span>AI Analysis</span>
          </div>
          <div class="secureguard-gemini-reasoning">${result.geminiReasoning}</div>
        </div>
        ` : ''}

        <div class="secureguard-factors-list">
          <h3>Risk Factors:</h3>
          ${result.riskScore.factors.map(factor => `
            <div class="secureguard-factor-item">
              <div>
                <strong>${factor.category}:</strong> ${factor.description}
                ${factor.details ? `<br><small style="color: #666;">${factor.details}</small>` : ''}
              </div>
              <span class="secureguard-factor-risk ${factor.risk.toLowerCase()}">${factor.risk}</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
        const closeButton = this.reportModal.querySelector('.secureguard-close-button');
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
                highlight.className = 'secureguard-suspicious-highlight';
                highlight.textContent = matchText;
                const tooltip = document.createElement('div');
                tooltip.className = 'secureguard-highlight-tooltip';
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
        errorDiv.textContent = `SecureGuard Error: ${message}`;
        document.body.appendChild(errorDiv);
        setTimeout(() => {
            errorDiv.remove();
        }, 5000);
    }
}
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new EmailScanner());
}
else {
    new EmailScanner();
}
//# sourceMappingURL=content.js.map