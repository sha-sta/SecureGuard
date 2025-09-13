"use strict";
class PopupController {
    constructor() {
        this.stats = {
            emailsScanned: 0,
            threatsBlocked: 0,
            protectionActive: true,
            protectionLevel: 'High'
        };
        this.init();
    }
    async init() {
        await this.loadStats();
        this.setupEventListeners();
        this.updateUI();
    }
    async loadStats() {
        try {
            const result = await chrome.storage.local.get(['extensionStats']);
            if (result.extensionStats) {
                this.stats = { ...this.stats, ...result.extensionStats };
            }
        }
        catch (error) {
            console.error('Failed to load stats:', error);
        }
    }
    async saveStats() {
        try {
            await chrome.storage.local.set({ extensionStats: this.stats });
        }
        catch (error) {
            console.error('Failed to save stats:', error);
        }
    }
    setupEventListeners() {
        const scanButton = document.getElementById('scan-current-email');
        scanButton?.addEventListener('click', () => this.scanCurrentEmail());
        const toggleButton = document.getElementById('toggle-protection');
        toggleButton?.addEventListener('click', () => this.toggleProtection());
        const settingsButton = document.getElementById('view-settings');
        settingsButton?.addEventListener('click', () => this.openSettings());
        const reportButton = document.getElementById('view-report');
        reportButton?.addEventListener('click', () => this.openReport());
    }
    updateUI() {
        const emailsScannedEl = document.getElementById('emails-scanned');
        const threatsBlockedEl = document.getElementById('threats-blocked');
        const protectionLevelEl = document.getElementById('protection-level');
        const statusEl = document.getElementById('status');
        const toggleButton = document.getElementById('toggle-protection');
        if (emailsScannedEl)
            emailsScannedEl.textContent = this.stats.emailsScanned.toString();
        if (threatsBlockedEl)
            threatsBlockedEl.textContent = this.stats.threatsBlocked.toString();
        if (protectionLevelEl)
            protectionLevelEl.textContent = this.stats.protectionLevel;
        if (statusEl) {
            statusEl.className = `status ${this.stats.protectionActive ? 'active' : 'inactive'}`;
            statusEl.textContent = this.stats.protectionActive ? '✅ Protection Active' : '❌ Protection Disabled';
        }
        if (toggleButton) {
            toggleButton.textContent = this.stats.protectionActive ? '⏸️ Disable Protection' : '▶️ Enable Protection';
        }
    }
    async scanCurrentEmail() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!tab.id) {
                this.showNotification('No active tab found', 'error');
                return;
            }
            const supportedSites = ['mail.google.com', 'outlook.live.com', 'outlook.office.com'];
            const isSupported = supportedSites.some(site => tab.url?.includes(site));
            if (!isSupported) {
                this.showNotification('Please navigate to Gmail or Outlook to scan emails', 'warning');
                return;
            }
            try {
                const response = await chrome.tabs.sendMessage(tab.id, {
                    type: 'MANUAL_SCAN_REQUEST'
                });
                if (!response || !response.success) {
                    throw new Error(response?.error || 'Content script not responding. Try refreshing the Gmail page.');
                }
                this.showNotification('Email scan initiated', 'success');
            }
            catch (error) {
                if (error instanceof Error && error.message.includes('Receiving end does not exist')) {
                    throw new Error('Content script not loaded. Please refresh the Gmail page and try again.');
                }
                throw error;
            }
            this.stats.emailsScanned++;
            await this.saveStats();
            this.updateUI();
            this.showNotification('Email scan initiated', 'success');
        }
        catch (error) {
            console.error('Failed to scan current email:', error);
            this.showNotification('Failed to scan email', 'error');
        }
    }
    async toggleProtection() {
        this.stats.protectionActive = !this.stats.protectionActive;
        await this.saveStats();
        this.updateUI();
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab.id) {
                chrome.tabs.sendMessage(tab.id, {
                    type: 'PROTECTION_STATUS_CHANGED',
                    active: this.stats.protectionActive
                });
            }
        }
        catch (error) {
            console.error('Failed to notify content script:', error);
        }
        this.showNotification(this.stats.protectionActive ? 'Protection enabled' : 'Protection disabled', this.stats.protectionActive ? 'success' : 'warning');
    }
    openSettings() {
        chrome.tabs.create({
            url: chrome.runtime.getURL('src/settings.html')
        });
    }
    openReport() {
        chrome.tabs.create({
            url: chrome.runtime.getURL('src/report.html')
        });
    }
    showNotification(message, type) {
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
        setTimeout(() => notification.style.opacity = '1', 10);
        setTimeout(() => {
            notification.style.opacity = '0';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
}
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new PopupController());
}
else {
    new PopupController();
}
//# sourceMappingURL=popup.js.map