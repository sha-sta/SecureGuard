// Popup script for SecureGuard extension

interface ExtensionStats {
  emailsScanned: number;
  threatsBlocked: number;
  protectionActive: boolean;
  protectionLevel: 'Low' | 'Medium' | 'High';
}

class PopupController {
  private stats: ExtensionStats = {
    emailsScanned: 0,
    threatsBlocked: 0,
    protectionActive: true,
    protectionLevel: 'High'
  };

  constructor() {
    this.init();
  }

  private async init(): Promise<void> {
    await this.loadStats();
    this.setupEventListeners();
    this.updateUI();
  }

  private async loadStats(): Promise<void> {
    try {
      const result = await chrome.storage.local.get(['extensionStats']);
      if (result.extensionStats) {
        this.stats = { ...this.stats, ...result.extensionStats };
      }
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  }

  private async saveStats(): Promise<void> {
    try {
      await chrome.storage.local.set({ extensionStats: this.stats });
    } catch (error) {
      console.error('Failed to save stats:', error);
    }
  }

  private setupEventListeners(): void {
    // Scan current email button
    const scanButton = document.getElementById('scan-current-email');
    scanButton?.addEventListener('click', () => this.scanCurrentEmail());

    // Toggle protection button
    const toggleButton = document.getElementById('toggle-protection');
    toggleButton?.addEventListener('click', () => this.toggleProtection());

    // Settings button
    const settingsButton = document.getElementById('view-settings');
    settingsButton?.addEventListener('click', () => this.openSettings());

    // Report button
    const reportButton = document.getElementById('view-report');
    reportButton?.addEventListener('click', () => this.openReport());
  }

  private updateUI(): void {
    // Update stats display
    const emailsScannedEl = document.getElementById('emails-scanned');
    const threatsBlockedEl = document.getElementById('threats-blocked');
    const protectionLevelEl = document.getElementById('protection-level');
    const statusEl = document.getElementById('status');
    const toggleButton = document.getElementById('toggle-protection');

    if (emailsScannedEl) emailsScannedEl.textContent = this.stats.emailsScanned.toString();
    if (threatsBlockedEl) threatsBlockedEl.textContent = this.stats.threatsBlocked.toString();
    if (protectionLevelEl) protectionLevelEl.textContent = this.stats.protectionLevel;

    // Update status
    if (statusEl) {
      statusEl.className = `status ${this.stats.protectionActive ? 'active' : 'inactive'}`;
      statusEl.textContent = this.stats.protectionActive ? '✅ Protection Active' : '❌ Protection Disabled';
    }

    // Update toggle button
    if (toggleButton) {
      toggleButton.textContent = this.stats.protectionActive ? '⏸️ Disable Protection' : '▶️ Enable Protection';
    }
  }

  private async scanCurrentEmail(): Promise<void> {
    try {
      // Get current active tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      if (!tab.id) {
        this.showNotification('No active tab found', 'error');
        return;
      }

      // Check if we're on a supported webmail site
      const supportedSites = ['mail.google.com', 'outlook.live.com', 'outlook.office.com'];
      const isSupported = supportedSites.some(site => tab.url?.includes(site));
      
      if (!isSupported) {
        this.showNotification('Please navigate to Gmail or Outlook to scan emails', 'warning');
        return;
      }

      // Send message to content script via background script
      try {
        const response = await chrome.tabs.sendMessage(tab.id, {
          type: 'MANUAL_SCAN_REQUEST'
        });
        
        if (!response || !response.success) {
          throw new Error(response?.error || 'Content script not responding. Try refreshing the Gmail page.');
        }
        
        this.showNotification('Email scan initiated', 'success');
      } catch (error) {
        if (error instanceof Error && error.message.includes('Receiving end does not exist')) {
          throw new Error('Content script not loaded. Please refresh the Gmail page and try again.');
        }
        throw error;
      }

      this.stats.emailsScanned++;
      await this.saveStats();
      this.updateUI();
      
      this.showNotification('Email scan initiated', 'success');
    } catch (error) {
      console.error('Failed to scan current email:', error);
      this.showNotification('Failed to scan email', 'error');
    }
  }

  private async toggleProtection(): Promise<void> {
    this.stats.protectionActive = !this.stats.protectionActive;
    await this.saveStats();
    this.updateUI();

    // Notify content scripts about protection status change
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab.id) {
        chrome.tabs.sendMessage(tab.id, {
          type: 'PROTECTION_STATUS_CHANGED',
          active: this.stats.protectionActive
        });
      }
    } catch (error) {
      console.error('Failed to notify content script:', error);
    }

    this.showNotification(
      this.stats.protectionActive ? 'Protection enabled' : 'Protection disabled',
      this.stats.protectionActive ? 'success' : 'warning'
    );
  }

  private openSettings(): void {
    // Open settings page in a new tab
    chrome.tabs.create({
      url: chrome.runtime.getURL('src/settings.html')
    });
  }

  private openReport(): void {
    // Open security report page in a new tab
    chrome.tabs.create({
      url: chrome.runtime.getURL('src/report.html')
    });
  }

  private showNotification(message: string, type: 'success' | 'warning' | 'error'): void {
    // Create a temporary notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 10px;
      left: 10px;
      right: 10px;
      padding: 10px;
      border-radius: 6px;
      color: white;
      font-size: 14px;
      z-index: 1000;
      opacity: 0;
      transition: opacity 0.3s;
      ${type === 'success' ? 'background: #4CAF50;' : ''}
      ${type === 'warning' ? 'background: #FF9800;' : ''}
      ${type === 'error' ? 'background: #f44336;' : ''}
    `;
    notification.textContent = message;

    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => notification.style.opacity = '1', 10);
    
    // Remove after 3 seconds
    setTimeout(() => {
      notification.style.opacity = '0';
      setTimeout(() => notification.remove(), 300);
    }, 3000);
  }
}

// Initialize popup when DOM is loaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => new PopupController());
} else {
  new PopupController();
}
