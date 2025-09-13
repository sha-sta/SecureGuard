// Content script for email scanning with on-demand analysis
import { EmailData, LinkData, AttachmentData, RiskScore, WebmailProvider } from './types';

interface DetailedAnalysisResult {
  success: boolean;
  riskScore: RiskScore;
  categoryScores: {
    header: number | null;
    content: number | null;
    links: number | null;
    attachments: number | null;
  };
  geminiReasoning: string;
  suspiciousTextRanges: Array<{
    text: string;
    reason: string;
    startIndex: number;
    endIndex: number;
  }>;
  error?: string;
}

class EmailScanner {
  private provider: WebmailProvider | null = null;
  private currentEmailContainer: HTMLElement | null = null;
  private scanButton: HTMLElement | null = null;
  private reportModal: HTMLElement | null = null;

  constructor() {
    this.detectProvider();
    this.init();
  }

  private detectProvider(): void {
    const hostname = window.location.hostname;
    
    if (hostname.includes('mail.google.com')) {
      this.provider = {
        name: 'gmail',
        selectors: {
          emailContainer: '[role="main"] [jsaction*="click"]',
          openEmailContainer: '[role="main"] [data-message-id]',
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

  private init(): void {
    if (!this.provider) return;

    this.injectStyles();
    this.observeForOpenEmails();
  }

  private injectStyles(): void {
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

  private observeForOpenEmails(): void {
    const observer = new MutationObserver(() => {
      this.checkForOpenEmail();
    });

    observer.observe(document.body, { childList: true, subtree: true });
    
    // Also check on URL changes (for Gmail SPA navigation)
    let currentUrl = window.location.href;
    setInterval(() => {
      if (window.location.href !== currentUrl) {
        currentUrl = window.location.href;
        setTimeout(() => this.checkForOpenEmail(), 500);
      }
    }, 1000);

    // Initial check
    setTimeout(() => this.checkForOpenEmail(), 1000);
  }

  private checkForOpenEmail(): void {
    const emailContainer = document.querySelector(this.provider!.selectors.openEmailContainer) as HTMLElement;
    
    if (emailContainer && emailContainer !== this.currentEmailContainer) {
      this.currentEmailContainer = emailContainer;
      this.showScanButton();
    } else if (!emailContainer && this.currentEmailContainer) {
      this.currentEmailContainer = null;
      this.hideScanButton();
      this.hideReport();
    }
  }

  private showScanButton(): void {
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

  private hideScanButton(): void {
    if (this.scanButton) {
      this.scanButton.remove();
      this.scanButton = null;
    }
  }

  private async scanCurrentEmail(): Promise<void> {
    if (!this.currentEmailContainer || !this.scanButton) return;

    // Update button to show scanning state
    this.scanButton.innerHTML = `
      <div class="spinner"></div>
      <span>Scanning...</span>
    `;
    this.scanButton.classList.add('scanning');
    (this.scanButton as HTMLButtonElement).disabled = true;

    try {
      const emailData = await this.extractEmailData(this.currentEmailContainer);
      const response = await chrome.runtime.sendMessage({
        type: 'ANALYZE_EMAIL_DETAILED',
        emailData
      });

      if (response.success) {
        this.showDetailedReport(response);
        this.highlightSuspiciousContent(response);
      } else {
        this.showError(response.error || 'Analysis failed');
      }
    } catch (error) {
      console.error('Error scanning email:', error);
      this.showError('Failed to scan email');
    } finally {
      // Reset button
      this.scanButton.innerHTML = `
        <span>🛡️</span>
        <span>Scan Email</span>
      `;
      this.scanButton.classList.remove('scanning');
      (this.scanButton as HTMLButtonElement).disabled = false;
    }
  }

  private async extractEmailData(container: HTMLElement): Promise<EmailData> {
    const fromElement = container.querySelector(this.provider!.selectors.fromField);
    const subjectElement = container.querySelector(this.provider!.selectors.subjectField);
    const bodyElement = container.querySelector(this.provider!.selectors.bodyField);

    // Extract headers from Gmail's interface
    const headers = this.extractHeaders(container);

    const emailData: EmailData = {
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

  private extractHeaders(container: HTMLElement): { [key: string]: string } {
    const headers: { [key: string]: string } = {};
    
    // Try to extract basic headers from Gmail's UI
    const fromElement = container.querySelector('[email]');
    if (fromElement) {
      headers['From'] = fromElement.getAttribute('email') || fromElement.textContent?.trim() || '';
    }

    const dateElement = container.querySelector('[data-tooltip*="GMT"], [title*="GMT"]');
    if (dateElement) {
      headers['Date'] = dateElement.getAttribute('data-tooltip') || dateElement.getAttribute('title') || '';
    }

    // Try to find message-id
    const messageId = container.getAttribute('data-message-id');
    if (messageId) {
      headers['Message-ID'] = messageId;
    }

    return headers;
  }

  private extractRecipients(container: HTMLElement): string[] {
    const recipients: string[] = [];
    const toElements = container.querySelectorAll('[email]');
    
    toElements.forEach(element => {
      const email = element.getAttribute('email') || element.textContent?.trim();
      if (email && !recipients.includes(email)) {
        recipients.push(email);
      }
    });

    return recipients;
  }

  private extractLinks(container: HTMLElement): LinkData[] {
    const links = container.querySelectorAll(this.provider!.selectors.linkSelector);
    const linkData: LinkData[] = [];

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

  private async extractAttachments(container: HTMLElement): Promise<AttachmentData[]> {
    const attachments = container.querySelectorAll(this.provider!.selectors.attachmentContainer);
    const attachmentData: AttachmentData[] = [];

    for (let i = 0; i < attachments.length; i++) {
      const attachment = attachments[i] as HTMLElement;
      const filename = attachment.textContent?.trim() || 
                      attachment.getAttribute('data-tooltip') ||
                      attachment.getAttribute('aria-label') ||
                      'unknown';
      
      let size = 0;
      let hash: string | undefined;
      
      // Try to extract file size
      const sizeText = attachment.getAttribute('data-size') || 
                      attachment.querySelector('[data-size]')?.getAttribute('data-size') ||
                      '';
      if (sizeText) {
        size = parseInt(sizeText) || 0;
      }
      
      // Try to get file hash if available
      const hashAttr = attachment.getAttribute('data-hash') ||
                      attachment.querySelector('[data-hash]')?.getAttribute('data-hash');
      if (hashAttr) {
        hash = hashAttr;
      }
      
      // Extract MIME type from extension
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

  private getMimeTypeFromExtension(extension: string): string {
    const mimeTypes: { [key: string]: string } = {
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

  private showDetailedReport(result: DetailedAnalysisResult): void {
    this.hideReport(); // Remove any existing report

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

    // Add close button functionality
    const closeButton = this.reportModal.querySelector('.secureguard-close-button');
    closeButton?.addEventListener('click', () => this.hideReport());

    // Close on backdrop click
    this.reportModal.addEventListener('click', (e) => {
      if (e.target === this.reportModal) {
        this.hideReport();
      }
    });

    document.body.appendChild(this.reportModal);
  }

  private getRiskClass(score: number | null): string {
    if (score === null) return 'na';
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
  }

  private highlightSuspiciousContent(result: DetailedAnalysisResult): void {
    if (!result.suspiciousTextRanges || !this.currentEmailContainer) return;

    const bodyElement = this.currentEmailContainer.querySelector(this.provider!.selectors.bodyField);
    if (!bodyElement) return;

    // Get the text content and create highlights
    const textContent = bodyElement.textContent || '';
    const highlights = result.suspiciousTextRanges
      .filter(range => range.startIndex < textContent.length)
      .sort((a, b) => b.startIndex - a.startIndex); // Sort in reverse order to avoid index shifting

    // Apply highlights by wrapping suspicious text
    highlights.forEach(highlight => {
      this.highlightTextInElement(bodyElement, highlight.text, highlight.reason);
    });
  }

  private highlightTextInElement(element: Element, searchText: string, reason: string): void {
    const walker = document.createTreeWalker(
      element,
      NodeFilter.SHOW_TEXT,
      null
    );

    const textNodes: Text[] = [];
    let node;
    while (node = walker.nextNode()) {
      textNodes.push(node as Text);
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

  private hideReport(): void {
    if (this.reportModal) {
      this.reportModal.remove();
      this.reportModal = null;
    }
  }

  private showError(message: string): void {
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

// Initialize the email scanner
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => new EmailScanner());
} else {
  new EmailScanner();
}