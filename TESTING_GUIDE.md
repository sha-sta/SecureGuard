# SecureGuard Testing Guide

## 1. Backend API Testing (Terminal)

### Start the Backend Server

```bash
cd /Users/sumei/SecureGuard/backend
source venv/bin/activate
python run_server.py
```

The server will start on `http://localhost:8000`

### Test API Endpoints

#### Health Check

```bash
curl -s http://localhost:8000/health | jq '.'
```

Expected response:

```json
{
  "status": "healthy",
  "timestamp": 1234567890.123
}
```

#### Basic Email Analysis

```bash
curl -X POST "http://localhost:8000/analyze-email" \
  -H "Content-Type: application/json" \
  -d @tests/sample_emails/phishing_example.json | jq '.success, .riskScore.overall'
```

Expected response: `true` and `"HIGH"`

#### Detailed Analysis (Chrome Extension Endpoint)

```bash
curl -X POST "http://localhost:8000/analyze-email-detailed" \
  -H "Content-Type: application/json" \
  -d @tests/sample_emails/phishing_example.json | jq '.'
```

#### Test Individual Components

```bash
# Test URL analysis
curl -X POST "http://localhost:8000/analyze-url" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://suspicious-site.tk"}'

# Test attachment analysis
curl -X POST "http://localhost:8000/analyze-attachment" \
  -H "Content-Type: application/json" \
  -d '{"filename": "invoice.pdf.exe", "file_hash": "abc123"}'
```

## 2. Chrome Extension Testing

### Build the Extension

```bash
cd /Users/sumei/SecureGuard/chrome-extension
npm run build
```

### Load Extension in Chrome

1. **Open Chrome Extensions Page**

   - Go to `chrome://extensions/`
   - OR click the 3-dot menu → More Tools → Extensions

2. **Enable Developer Mode**

   - Toggle "Developer mode" in the top-right corner

3. **Load Unpacked Extension**

   - Click "Load unpacked"
   - Navigate to `/Users/sumei/SecureGuard/chrome-extension/dist/`
   - Select the `dist` folder and click "Select"

4. **Verify Installation**
   - You should see "SecureGuard Email Scam Detection" in your extensions list
   - The extension icon should appear in the Chrome toolbar

### Test the Extension

#### 1. Test in Gmail

1. **Open Gmail**

   - Go to `https://gmail.com`
   - Log into your account

2. **Open an Email**

   - Click on any email to open it
   - Look for the **"Scan Email"** button that should appear

3. **Test the Scan Feature**
   - Click the "Scan Email" button
   - A modal should appear with:
     - Overall risk score
     - Category breakdowns (Header, Content, Attachments, URLs)
     - Gemini AI reasoning (if available)
     - Highlighted suspicious text in the email

#### 2. Test Extension Popup

1. **Click Extension Icon**
   - Click the SecureGuard icon in the Chrome toolbar
   - The popup should show extension status and options

#### 3. Test Error Handling

1. **Test Without Backend**

   - Stop the backend server
   - Try scanning an email
   - Should show an error message about server connectivity

2. **Test with Backend**
   - Restart the backend server
   - Try scanning again
   - Should work normally

### Debugging the Extension

#### View Console Logs

1. **Content Script Logs**

   - Open Gmail
   - Press F12 to open DevTools
   - Go to Console tab
   - Look for SecureGuard-related logs

2. **Background Script Logs**

   - Go to `chrome://extensions/`
   - Find SecureGuard extension
   - Click "service worker" link
   - View logs in the opened DevTools window

3. **Popup Logs**
   - Right-click the extension icon
   - Select "Inspect popup"
   - View logs in the DevTools console

#### Common Issues and Solutions

1. **Extension Not Loading**

   - Check that all files are in the `dist/` folder
   - Verify manifest.json is valid
   - Check console for errors

2. **Scan Button Not Appearing**

   - Check if you're on a supported email provider (Gmail)
   - Verify the email is fully loaded
   - Check console for content script errors

3. **API Calls Failing**

   - Ensure backend server is running on localhost:8000
   - Check browser console for CORS or network errors
   - Verify API endpoints are responding

4. **Permissions Issues**
   - Check that host_permissions include the email provider domains
   - Reload the extension after making changes

## 3. Integration Testing

### Test Complete Flow

1. Start backend server
2. Load extension in Chrome
3. Open Gmail and select an email with:
   - Suspicious subject line
   - External links
   - Attachments
4. Click "Scan Email"
5. Verify all analysis results appear correctly

### Test Different Email Types

- **Safe emails**: Should show LOW risk
- **Suspicious emails**: Should show MEDIUM risk
- **Phishing emails**: Should show HIGH risk
- **Emails with attachments**: Should analyze file types
- **Emails with links**: Should check URL reputation

## 4. Performance Testing

### Backend Performance

```bash
# Test response times
time curl -X POST "http://localhost:8000/analyze-email-detailed" \
  -H "Content-Type: application/json" \
  -d @tests/sample_emails/phishing_example.json
```

### Extension Performance

- Monitor memory usage in Chrome Task Manager
- Check for memory leaks during extended use
- Test with large emails and many attachments

## 5. Configuration Testing

### Environment Variables

Test with different API keys:

```bash
# Test without Gemini API key
export GEMINI_API_KEY=""

# Test without VirusTotal API key
export VIRUSTOTAL_API_KEY=""

# Restart server and test functionality
```

### Extension Configuration

Test extension behavior with different:

- Email providers (Gmail, Outlook)
- Email layouts and themes
- Browser zoom levels
- Multiple tabs open

## Troubleshooting

### Backend Issues

- **Port already in use**: Kill existing processes with `pkill -f "python run_server.py"`
- **Missing dependencies**: Run `pip install -r requirements.txt`
- **API key errors**: Check `.env` file configuration

### Extension Issues

- **Not working in incognito**: Enable "Allow in incognito" in extension settings
- **Permissions denied**: Check manifest.json host_permissions
- **Updates not applying**: Click "Reload" button for the extension

### General Tips

- Always check browser console for error messages
- Use Chrome DevTools Network tab to debug API calls
- Test with different email content and structures
- Verify all components work independently before testing integration
