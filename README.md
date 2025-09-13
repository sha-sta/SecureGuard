# 🛡️ SecureGuard - AI-Powered Email Scam Detection

SecureGuard is a comprehensive email security solution that combines a Chrome extension with a powerful backend API to detect phishing, scams, and malicious emails in real-time. It works seamlessly with Gmail and Outlook webmail clients.

## ✨ Features

### Chrome Extension

- **Real-time Email Analysis**: Automatically scans emails as you read them
- **Visual Warnings**: Clear, non-intrusive banners and tooltips for threats
- **Link Protection**: Highlights suspicious links with hover warnings
- **Attachment Scanning**: Identifies potentially dangerous attachments
- **Gmail & Outlook Support**: Works with popular webmail clients

### Backend API

- **Multi-layered Analysis**:
  - Header/metadata validation (SPF/DKIM/DMARC)
  - URL reputation checking (Google Safe Browsing, VirusTotal)
  - Attachment analysis with hash checking
  - AI-powered content analysis using Google Gemini
- **Risk Scoring**: Intelligent risk assessment with detailed explanations
- **Fast & Scalable**: Built with FastAPI for high performance
- **Comprehensive Logging**: Detailed analysis logs for security teams

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Node.js 16+ (for Chrome extension)
- Chrome browser

### Installation

1. **Clone and setup:**

   ```bash
   git clone <repository-url>
   cd SecureGuard
   chmod +x setup.sh
   ./setup.sh
   ```

2. **Configure API keys** (optional but recommended):

   ```bash
   cp backend/env.example backend/.env
   # Edit backend/.env with your API keys
   ```

3. **Start the backend server:**

   ```bash
   cd backend
   python run_server.py
   ```

4. **Install Chrome extension:**
   - Open Chrome and go to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked" and select `chrome-extension/dist/`

## 🔧 Configuration

### API Keys (Optional)

Add these to `backend/.env` for enhanced protection:

- `VIRUSTOTAL_API_KEY`: For malware detection
- `GOOGLE_SAFE_BROWSING_API_KEY`: For URL reputation
- `GEMINI_API_KEY`: For AI content analysis

### Risk Scoring Weights

Customize analysis weights in `backend/.env`:

```
HEADER_ANALYSIS_WEIGHT=0.25
LINK_ANALYSIS_WEIGHT=0.30
ATTACHMENT_ANALYSIS_WEIGHT=0.20
CONTENT_ANALYSIS_WEIGHT=0.25
```

## 📖 How It Works

1. **Email Detection**: Content script detects when you open an email
2. **Data Extraction**: Safely extracts email metadata, links, and attachments
3. **Backend Analysis**: Sends data to backend for multi-layered security analysis
4. **Risk Assessment**: AI and rule-based systems calculate risk score
5. **Visual Warnings**: Extension displays warnings directly in your email client

## 🛡️ Security Analysis

### Header Analysis

- SPF/DKIM/DMARC validation
- Sender IP/domain reputation
- Timestamp anomaly detection
- Domain age and typosquatting checks

### Link Analysis

- URL reputation via multiple threat intelligence sources
- Static analysis for obfuscation and suspicious patterns
- Redirect chain analysis
- Typosquatting detection

### Attachment Analysis

- File hash reputation checking
- Static analysis for macros and JavaScript
- Suspicious extension detection
- Double extension and disguise detection

### Content Analysis

- AI-powered phishing detection using Google Gemini
- Social engineering tactic identification
- Urgency and pressure tactic detection
- Brand impersonation detection

## 🎯 Risk Scoring

SecureGuard uses a sophisticated risk scoring system:

- **Low Risk (0-30)**: ✅ Email appears legitimate
- **Medium Risk (31-60)**: ⚡ Exercise caution
- **High Risk (61-100)**: ⚠️ Likely scam or phishing

Risk factors are weighted by category and combined using compound risk calculation for accurate threat assessment.

## 🔌 API Documentation

Once the backend is running, visit:

- **Interactive API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health
- **Stats Endpoint**: http://localhost:8000/stats

### Example API Usage

```bash
curl -X POST "http://localhost:8000/analyze-email" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "suspicious@example.com",
    "to": ["user@company.com"],
    "subject": "Urgent: Verify your account",
    "body": "Click here to verify your account immediately...",
    "headers": {},
    "links": [{"url": "http://suspicious-site.com", "displayText": "Verify Now", "position": 0}],
    "attachments": [],
    "timestamp": "2024-01-01T12:00:00Z",
    "messageId": "12345"
  }'
```

## 🏗️ Architecture

```
┌─────────────────┐    HTTPS     ┌──────────────────┐
│ Chrome Extension│ ──────────── │ FastAPI Backend  │
│                 │              │                  │
│ • Content Script│              │ • Header Analysis│
│ • Popup UI      │              │ • Link Analysis  │
│ • Background    │              │ • Attachment     │
│   Service       │              │ • Content (AI)   │
└─────────────────┘              │ • Risk Scoring   │
                                 └──────────────────┘
                                           │
                                           ▼
                                 ┌──────────────────┐
                                 │ External APIs    │
                                 │                  │
                                 │ • VirusTotal     │
                                 │ • Safe Browsing  │
                                 │ • Gemini AI      │
                                 └──────────────────┘
```

## 🧪 Testing

### Test the Backend

```bash
cd backend
python -m pytest tests/
```

### Test Email Analysis

Use the included test emails in `backend/tests/sample_emails/`:

```bash
# Test with a suspicious email
curl -X POST "http://localhost:8000/analyze-email" \
  -H "Content-Type: application/json" \
  -d @tests/sample_emails/phishing_example.json
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

SecureGuard is a security tool designed to assist in identifying potential email threats. It should not be considered 100% accurate and should be used in conjunction with other security measures and human judgment. Always verify suspicious emails through alternative channels when in doubt.

## 🆘 Support

- **Documentation**: Check the `/docs` endpoint when running the backend
- **Issues**: Report bugs and feature requests via GitHub Issues
- **Security**: For security vulnerabilities, please email security@secureguard.com

---

**Made with ❤️ for email security**
