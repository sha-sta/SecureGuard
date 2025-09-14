// Content script for email scanning with on-demand analysis

// Inline type definitions to avoid module issues
interface EmailData {
  from: string;
  to: string[];
  subject: string;
  body: string;
  headers: Record<string, string>;
  links: LinkData[];
  attachments: AttachmentData[];
  timestamp: string;
  messageId: string;
}

interface LinkData {
  url: string;
  displayText: string;
  position: number;
}

interface AttachmentData {
  filename: string;
  mimeType: string;
  size: number;
  hash?: string;
}

interface RiskScore {
  overall: 'LOW' | 'MEDIUM' | 'HIGH';
  score: number;
  factors: RiskFactor[];
  explanation: string;
}

interface RiskFactor {
  category: 'HEADER' | 'LINK' | 'ATTACHMENT' | 'CONTENT';
  risk: 'LOW' | 'MEDIUM' | 'HIGH';
  score: number;
  description: string;
  details?: string;
}

interface WebmailProvider {
  name: string;
  selectors: {
    emailContainer: string;
    openEmailContainer: string;
    fromField: string;
    toField: string;
    subjectField: string;
    bodyField: string;
    attachmentContainer: string;
    linkSelector: string;
    headerContainer: string;
  };
}

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
    console.log('veris: Content script loaded on:', window.location.hostname);
    this.detectProvider();
    console.log('veris: Provider detected:', this.provider?.name);
    this.init();
    this.setupMessageListener();
  }

  private setupMessageListener(): void {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.type === 'MANUAL_SCAN_REQUEST') {
        console.log('veris: Received manual scan request from popup');
        if (this.currentEmailContainer && this.scanButton) {
          this.scanCurrentEmail();
          sendResponse({ success: true });
        } else {
          sendResponse({ success: false, error: 'No email currently open' });
        }
        return true; // Keep message channel open
      }
    });
  }

  private detectProvider(): void {
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

  private init(): void {
    if (!this.provider) return;

    this.injectStyles();
    this.observeForOpenEmails();
  }

  private injectStyles(): void {
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
        white-space: pre-line;
        margin-left: 10px;
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

      .veris-link-analysis-section {
        margin-bottom: 24px;
        padding: 20px;
        background: #f8f9fa;
        border-radius: 8px;
        border-left: 4px solid #2196F3;
      }

      .veris-link-analysis-title {
        font-size: 18px;
        font-weight: 600;
        color: #1976D2;
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .veris-link-summary {
        background: white;
        padding: 16px;
        border-radius: 6px;
        margin-bottom: 16px;
        border: 1px solid #e0e0e0;
      }

      .veris-link-stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
        gap: 12px;
      }

      .veris-link-stat {
        display: flex;
        flex-direction: column;
        align-items: center;
        text-align: center;
      }

      .veris-link-stat-label {
        font-size: 12px;
        color: #666;
        font-weight: 500;
        margin-bottom: 4px;
      }

      .veris-link-stat-value {
        font-size: 16px;
        font-weight: 700;
        color: #333;
      }

      .veris-risk-high {
        color: #cc0000 !important;
      }

      .veris-risk-medium {
        color: #e67300 !important;
      }

      .veris-risk-low {
        color: #2e7d32 !important;
      }

      .veris-threat-count {
        color: #cc0000;
        font-weight: 700;
      }

      .veris-link-details-title {
        font-size: 16px;
        font-weight: 600;
        color: #333;
        margin: 0 0 12px 0;
      }

      .veris-link-item {
        background: white;
        border: 1px solid #e0e0e0;
        border-radius: 6px;
        padding: 12px;
        margin-bottom: 12px;
      }

      .veris-link-item.veris-risk-high {
        border-left: 4px solid #ff4444;
        background: #fff5f5;
      }

      .veris-link-item.veris-risk-medium {
        border-left: 4px solid #ff8800;
        background: #fff8f0;
      }

      .veris-link-item.veris-risk-low {
        border-left: 4px solid #4CAF50;
        background: #f8fff8;
      }

      .veris-link-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 8px;
      }

      .veris-link-number {
        font-weight: 600;
        color: #666;
        font-size: 14px;
      }

      .veris-link-risk-badge {
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 10px;
        font-weight: 600;
        text-transform: uppercase;
      }

      .veris-link-risk-badge.veris-risk-high {
        background: #ff4444;
        color: white;
      }

      .veris-link-risk-badge.veris-risk-medium {
        background: #ff8800;
        color: white;
      }

      .veris-link-risk-badge.veris-risk-low {
        background: #4CAF50;
        color: white;
      }

      .veris-link-url, .veris-link-threat, .veris-link-threat-type, .veris-link-score {
        margin-bottom: 6px;
        font-size: 14px;
        line-height: 1.4;
      }

      .veris-link-url-text {
        font-family: 'Courier New', monospace;
        background: #f5f5f5;
        padding: 2px 4px;
        border-radius: 3px;
        font-size: 12px;
        word-break: break-all;
      }

      .veris-threat-type-malware {
        color: #cc0000;
        font-weight: 600;
      }

      .veris-threat-type-social_engineering {
        color: #e67300;
        font-weight: 600;
      }

      .veris-threat-type-unwanted_software {
        color: #9c27b0;
        font-weight: 600;
      }

      .veris-threat-type-clean {
        color: #2e7d32;
        font-weight: 600;
      }

      .veris-no-links {
        text-align: center;
        color: #666;
        font-style: italic;
        padding: 20px;
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

  private showScanButton(): void {
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

  private hideScanButton(): void {
    if (this.scanButton) {
      this.scanButton.remove();
      this.scanButton = null;
    }
  }

  private async scanCurrentEmail(): Promise<void> {
    console.log('veris: Starting email scan...');
    
    if (!this.currentEmailContainer || !this.scanButton) {
      console.error('veris: Missing email container or scan button');
      return;
    }

    // Use web scraping to extract and analyze email content directly
    try {
      const payload = {
        url: location.href,
        timestamp: new Date().toISOString(),
        html: document.documentElement.outerHTML
      };

      console.log('SecureGuard: Sending HTML for analysis...');
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
      
      const analysisResponse = await fetch('http://localhost:8000/analyze-email-from-html', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);

      if (!analysisResponse.ok) {
        throw new Error(`Analysis failed: HTTP ${analysisResponse.status}`);
      }

      const analysisResult = await analysisResponse.json();
      console.log('SecureGuard: Analysis result:', analysisResult);

      if (analysisResult.success) {
        // Convert backend response to match expected format
        const detailedResult = {
          success: true,
          riskScore: analysisResult.riskScore,
          categoryScores: this.calculateCategoryScores(analysisResult.riskScore.factors),
          geminiReasoning: this.extractGeminiReasoning(analysisResult.riskScore.factors),
          suspiciousTextRanges: [] // We'll implement this later
        };

        this.showDetailedReport(detailedResult);
        this.highlightSuspiciousContent(detailedResult);
        return; // Exit early since we got the result
      } else {
        throw new Error(analysisResult.error || 'Analysis failed');
      }
    } catch (htmlAnalysisError) {
      console.error('SecureGuard: HTML analysis failed, falling back to DOM extraction:', htmlAnalysisError);
      if (htmlAnalysisError instanceof Error && htmlAnalysisError.name === 'AbortError') {
        this.showError('Analysis timed out after 30 seconds. Please try again.');
        return;
      }
      // Fall back to the original DOM-based extraction method
    }


    // Update button to show scanning state
    this.scanButton.innerHTML = `
      <div class="spinner"></div>
      <span>Scanning...</span>
    `;
    this.scanButton.classList.add('scanning');
    (this.scanButton as HTMLButtonElement).disabled = true;

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
      // Reset button
      this.scanButton.innerHTML = `
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

    // If no recipients found, add a default one (current user)
    if (recipients.length === 0) {
      recipients.push('user@example.com');
    }

    console.log('veris: Extracted recipients:', recipients);
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

  private calculateCategoryScores(factors: RiskFactor[]): {
    header: number | null;
    content: number | null;
    links: number | null;
    attachments: number | null;
  } {
    const categories = {
      header: [] as number[],
      content: [] as number[],
      links: [] as number[],
      attachments: [] as number[]
    };

    factors.forEach(factor => {
      // Map backend categories to frontend categories
      let categoryKey: keyof typeof categories;
      switch (factor.category.toUpperCase()) {
        case 'HEADER':
          categoryKey = 'header';
          break;
        case 'CONTENT':
          categoryKey = 'content';
          break;
        case 'LINK':
          categoryKey = 'links';
          break;
        case 'ATTACHMENT':
          categoryKey = 'attachments';
          break;
        default:
          return; // Skip unknown categories
      }
      
      if (categories[categoryKey]) {
        categories[categoryKey].push(factor.score);
      }
    });

    return {
      header: categories.header.length > 0 ? Math.max(...categories.header) : null,
      content: categories.content.length > 0 ? Math.max(...categories.content) : null,
      links: categories.links.length > 0 ? Math.max(...categories.links) : null,
      attachments: categories.attachments.length > 0 ? Math.max(...categories.attachments) : null
    };
  }

  private extractGeminiReasoning(factors: RiskFactor[]): string {
    const aiFactors = factors.filter(factor => 
      factor.category === 'CONTENT' && 
      (factor.description.includes('•') || factor.description.includes('AI Analysis:') || factor.description.includes('Gemini'))
    );

    if (aiFactors.length > 0) {
      return aiFactors.map(factor => {
        // Remove "AI Analysis:" prefix and preserve bullet points
        let reasoning = factor.description.replace('AI Analysis:', '').trim();
        
        // If it doesn't already have bullet points, convert newlines to bullet points
        if (!reasoning.includes('•') && reasoning.includes('\n')) {
          reasoning = reasoning.split('\n')
            .filter(line => line.trim())
            .map(line => line.trim().startsWith('•') ? line : `• ${line.trim()}`)
            .join('\n');
        }
        
        return reasoning;
      }).join('\n\n');
    }

    return 'No AI analysis available for this email.';
  }

  private extractLinkAnalysis(factors: RiskFactor[]): Array<{
    url: string;
    threat: string;
    threatType: string;
    riskLevel: string;
    score: number;
  }> {
    const linkFactors = factors.filter(factor => factor.category === 'LINK');
    
    return linkFactors.map(factor => {
      // Extract URL from details (format: "Position: 0, URL: http://example.com..., Threat Type: MALWARE" or "Position: 0, URL: http://example.com..., Status: Clean")
      const urlMatch = factor.details?.match(/URL: ([^,]+)/);
      const threatTypeMatch = factor.details?.match(/Threat Type: (\w+)/);
      const statusMatch = factor.details?.match(/Status: (\w+)/);
      
      return {
        url: urlMatch ? urlMatch[1].replace('...', '') : 'Unknown URL',
        threat: factor.description,
        threatType: threatTypeMatch ? threatTypeMatch[1] : (statusMatch ? statusMatch[1] : 'Unknown'),
        riskLevel: factor.risk,
        score: factor.score
      };
    });
  }

  private generateLinkAnalysisSection(factors: RiskFactor[]): string {
    const linkAnalysis = this.extractLinkAnalysis(factors);
    const linkFactors = factors.filter(factor => factor.category === 'LINK');
    
    if (linkFactors.length === 0) {
      return `
        <div class="veris-link-analysis-section">
          <div class="veris-link-analysis-title">
            <span>Link Analysis</span>
          </div>
          <div class="veris-link-analysis-content">
            <p class="veris-no-links">No links found in this email to analyze.</p>
          </div>
        </div>
      `;
    }

    // Calculate average score
    const totalScore = linkFactors.reduce((sum, factor) => sum + factor.score, 0);
    const averageScore = Math.round(totalScore / linkFactors.length);
    const averageRisk = averageScore >= 70 ? 'HIGH' : averageScore >= 40 ? 'MEDIUM' : 'LOW';

    // Count clean vs threat links
    const threatLinks = linkAnalysis.filter(link => link.riskLevel !== 'LOW');
    const cleanLinks = linkAnalysis.length - threatLinks.length;

    return `
      <div class="veris-link-analysis-section">
        <div class="veris-link-analysis-title">
          <span>Link Analysis</span>
        </div>
        <div class="veris-link-analysis-content">
          <div class="veris-link-summary">
            <div class="veris-link-stats">
              <div class="veris-link-stat">
                <span class="veris-link-stat-label">Total Links:</span>
                <span class="veris-link-stat-value">${linkAnalysis.length}</span>
              </div>
              <div class="veris-link-stat">
                <span class="veris-link-stat-label">Average Risk:</span>
                <span class="veris-link-stat-value veris-risk-${averageRisk.toLowerCase()}">${averageRisk} (${averageScore}%)</span>
              </div>
              <div class="veris-link-stat">
                <span class="veris-link-stat-label">Threats Found:</span>
                <span class="veris-link-stat-value ${threatLinks.length > 0 ? 'veris-threat-count' : ''}">${threatLinks.length}</span>
              </div>
              <div class="veris-link-stat">
                <span class="veris-link-stat-label">Clean Links:</span>
                <span class="veris-link-stat-value">${cleanLinks}</span>
              </div>
            </div>
          </div>
          
          ${linkAnalysis.length > 0 ? `
          <div class="veris-link-details">
            <h4 class="veris-link-details-title">Link Details:</h4>
            ${linkAnalysis.map((link, index) => `
              <div class="veris-link-item veris-risk-${link.riskLevel.toLowerCase()}">
                <div class="veris-link-header">
                  <span class="veris-link-number">#${index + 1}</span>
                  <span class="veris-link-risk-badge veris-risk-${link.riskLevel.toLowerCase()}">${link.riskLevel}</span>
                </div>
                <div class="veris-link-url">
                  <strong>URL:</strong> <span class="veris-link-url-text">${link.url.length > 60 ? link.url.substring(0, 60) + '...' : link.url}</span>
                </div>
                <div class="veris-link-threat">
                  <strong>Analysis:</strong> ${link.threat}
                </div>
                ${link.threatType !== 'Unknown' ? `
                <div class="veris-link-threat-type">
                  <strong>Threat Type:</strong> <span class="veris-threat-type-${link.threatType.toLowerCase()}">${link.threatType}</span>
                </div>
                ` : ''}
                <div class="veris-link-score">
                  <strong>Risk Score:</strong> ${link.score}%
                </div>
              </div>
            `).join('')}
          </div>
          ` : ''}
        </div>
      </div>
    `;
  }

  private showDetailedReport(result: DetailedAnalysisResult): void {
    this.hideReport(); // Remove any existing report

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
          <div class="veris-gemini-reasoning">${result.geminiReasoning}</div>
        </div>
        ` : ''}

        ${this.generateLinkAnalysisSection(result.riskScore.factors)}
      </div>
    `;

    // Add close button functionality
    const closeButton = this.reportModal.querySelector('.veris-close-button');
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

  private generateProgressBar(score: number | null, riskClass: string): string {
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

    // Calculate the stroke-dashoffset based on score
    // Total path length is approximately 110 for the semicircle
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
    errorDiv.textContent = `veris Error: ${message}`;
    
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