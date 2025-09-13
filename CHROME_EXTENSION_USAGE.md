# 🛡️ SecureGuard Chrome Extension - User Guide

## Overview

The SecureGuard Chrome extension now provides **on-demand email scanning** with detailed security analysis and visual threat highlighting directly in Gmail.

## ✨ New Features

### 🔘 **Scan Button**

- **Automatic Detection**: When you open an email in Gmail, a "Scan Email" button appears in the top-right corner
- **One-Click Analysis**: Click the button to initiate a comprehensive security scan
- **Visual Feedback**: Button shows scanning progress with a spinner animation

### 📊 **Detailed Security Report**

After scanning, you'll see a comprehensive report modal with:

#### **Overall Risk Assessment**

- **Risk Level**: LOW, MEDIUM, or HIGH with color-coded display
- **Risk Score**: Numerical score from 0-100
- **Visual Indicators**:
  - 🛡️ LOW (Green): Safe email
  - ⚡ MEDIUM (Orange): Caution advised
  - ⚠️ HIGH (Red): Dangerous email

#### **Category Breakdown**

Individual risk scores for each analysis category:

1. **📧 Headers** (0-100 or N/A)

   - Email authentication (SPF/DKIM/DMARC)
   - Sender reputation and validation
   - Domain age and suspicious patterns

2. **📝 Content** (0-100 or N/A)

   - AI-powered phishing detection
   - Social engineering tactics
   - Urgency and threat language
   - Brand impersonation attempts

3. **🔗 Links** (0-100 or N/A)

   - URL reputation via VirusTotal
   - Typosquatting detection
   - Suspicious redirect patterns
   - Display text vs actual URL mismatches

4. **📎 Attachments** (0-100 or N/A)
   - File hash reputation via VirusTotal
   - Dangerous file extensions
   - MIME type validation
   - Static malware analysis

#### **🤖 AI Analysis Section**

- **Gemini AI Reasoning**: Detailed explanation of why content was flagged
- **Suspicious Elements**: Specific patterns and indicators found
- **Confidence Score**: AI's confidence in its assessment

#### **🔍 Risk Factors List**

Complete breakdown of all detected threats:

- **Category**: Which analysis module detected the risk
- **Risk Level**: LOW/MEDIUM/HIGH classification
- **Description**: What was found
- **Details**: Additional context and specifics

### 🎯 **Content Highlighting**

- **Red Underlines**: Suspicious text in the email is highlighted in red
- **Hover Tooltips**: Hover over highlighted text to see why it was flagged
- **Real-time Marking**: Highlights appear immediately after analysis

## 🚀 How to Use

### 1. **Installation**

```bash
# Build the extension
cd chrome-extension
npm run build

# Load in Chrome
1. Open Chrome → More Tools → Extensions
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `chrome-extension/dist` folder
```

### 2. **Usage Workflow**

1. **Open Gmail** and navigate to any email
2. **Look for the Scan Button** in the top-right corner (🛡️ Scan Email)
3. **Click to Scan** - the button will show "Scanning..." with a spinner
4. **Review the Report** - a detailed modal will appear with results
5. **Check Highlighted Text** - suspicious content will be underlined in red
6. **Close Report** - click the × or click outside the modal

### 3. **Interpreting Results**

#### **🟢 LOW Risk (0-39)**

- Email appears legitimate
- Minimal security concerns
- Safe to interact with normally

#### **🟠 MEDIUM Risk (40-69)**

- Some suspicious elements detected
- Exercise caution before clicking links or opening attachments
- Verify sender authenticity if unsure

#### **🔴 HIGH Risk (70-100)**

- Strong indicators of phishing/scam
- **DO NOT** click links or open attachments
- **DO NOT** provide personal information
- Consider reporting as spam

## 🛠️ Technical Details

### **Backend Integration**

- **VirusTotal API**: Real-time malware and URL reputation checking
- **AI Analysis**: Advanced content analysis for phishing detection
- **Multi-layered Scanning**: Headers, content, links, and attachments

### **Privacy & Security**

- **Local Processing**: Email content analyzed securely via your local backend
- **No Data Storage**: Analysis results are not stored permanently
- **HTTPS Communication**: All API calls use secure connections

### **Performance**

- **Async Processing**: Non-blocking analysis doesn't freeze Gmail
- **Smart Caching**: Results cached to avoid repeated scans
- **Rate Limiting**: Respects VirusTotal API limits

## 🔧 Configuration

### **API Keys** (Optional but Recommended)

Add these to `backend/.env` for enhanced protection:

```env
VIRUSTOTAL_API_KEY=your-virustotal-api-key
GOOGLE_SAFE_BROWSING_API_KEY=your-google-safe-browsing-key
GEMINI_API_KEY=your-gemini-api-key
```

### **Risk Thresholds**

Customize in `backend/.env`:

```env
LOW_RISK_THRESHOLD=30
MEDIUM_RISK_THRESHOLD=60
HIGH_RISK_THRESHOLD=80
```

## 🎯 Best Practices

### **For Users**

1. **Always Scan Suspicious Emails**: Use the scan button for any unexpected emails
2. **Trust the Highlighting**: Pay attention to red-highlighted suspicious text
3. **Read AI Reasoning**: The Gemini analysis provides valuable context
4. **Verify Before Acting**: When in doubt, verify with the sender through other means

### **For Administrators**

1. **Monitor API Usage**: Keep track of VirusTotal API call limits
2. **Update Regularly**: Keep the extension and backend updated
3. **Review Logs**: Check backend logs for analysis patterns
4. **Customize Thresholds**: Adjust risk thresholds based on your organization's needs

## 🚨 Troubleshooting

### **Scan Button Not Appearing**

- Refresh the Gmail page
- Ensure the extension is enabled in Chrome
- Check that you're viewing an individual email (not the inbox)

### **Analysis Fails**

- Ensure the backend server is running (`python run_server.py`)
- Check network connectivity to localhost:8000
- Verify API keys are configured correctly

### **Slow Analysis**

- VirusTotal API has rate limits (4 requests/minute for free tier)
- Large emails take longer to process
- Network connectivity affects API response times

## 📞 Support

- **Documentation**: Check the main README.md for setup instructions
- **API Docs**: Visit http://localhost:8000/docs when server is running
- **Logs**: Check browser console and backend logs for error details

---

**🛡️ Stay Safe Online!** The SecureGuard extension is your first line of defense against email-based threats. Always combine automated analysis with your own judgment and security awareness.
