// Background script for SecureGuard extension

chrome.runtime.onInstalled.addListener(() => {
  console.log('SecureGuard extension installed');
});

// Handle messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('SecureGuard Background: Received message:', request.type);
  
  if (request.type === 'ANALYZE_EMAIL') {
    console.log('SecureGuard Background: Processing ANALYZE_EMAIL');
    analyzeEmail(request.emailData)
      .then(response => {
        console.log('SecureGuard Background: ANALYZE_EMAIL response:', response);
        sendResponse(response);
      })
      .catch(error => {
        console.error('SecureGuard Background: ANALYZE_EMAIL error:', error);
        sendResponse({ success: false, error: error.message });
      });
    return true; // Keep the message channel open for async response
  } else if (request.type === 'ANALYZE_EMAIL_DETAILED') {
    console.log('SecureGuard Background: Processing ANALYZE_EMAIL_DETAILED');
    analyzeEmailDetailed(request.emailData)
      .then(response => {
        console.log('SecureGuard Background: ANALYZE_EMAIL_DETAILED response:', response);
        sendResponse(response);
      })
      .catch(error => {
        console.error('SecureGuard Background: ANALYZE_EMAIL_DETAILED error:', error);
        sendResponse({ success: false, error: error.message });
      });
    return true; // Keep the message channel open for async response
  }
  
  console.log('SecureGuard Background: Unknown message type:', request.type);
});

async function analyzeEmail(emailData: any): Promise<any> {
  const API_BASE_URL = 'http://localhost:8000'; // Change to your backend URL
  
  try {
    const response = await fetch(`${API_BASE_URL}/analyze-email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(emailData),
    });

    if (!response.ok) {
      throw new Error(`API request failed: ${response.status}`);
    }

    const result = await response.json();
    return { success: true, riskScore: result };
  } catch (error) {
    console.error('Email analysis failed:', error);
    return { 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    };
  }
}

async function analyzeEmailDetailed(emailData: any): Promise<any> {
  const API_BASE_URL = 'http://localhost:8000'; // Change to your backend URL
  
  console.log('SecureGuard Background: Making API call to:', `${API_BASE_URL}/analyze-email-detailed`);
  console.log('SecureGuard Background: Email data being sent:', emailData);
  
  try {
    const response = await fetch(`${API_BASE_URL}/analyze-email-detailed`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(emailData),
    });

    console.log('SecureGuard Background: API response status:', response.status);

    if (!response.ok) {
      const errorText = await response.text();
      console.error('SecureGuard Background: API error response:', errorText);
      throw new Error(`API request failed: ${response.status} - ${errorText}`);
    }

    const result = await response.json();
    console.log('SecureGuard Background: API success response:', result);
    
    // Transform the result to match our detailed interface
    const categoryScores = calculateCategoryScores(result.riskScore.factors);
    
    return { 
      success: true, 
      riskScore: result.riskScore,
      categoryScores: categoryScores,
      geminiReasoning: extractGeminiReasoning(result.riskScore.factors),
      suspiciousTextRanges: extractSuspiciousTextRanges(result.riskScore.factors, emailData.body)
    };
  } catch (error) {
    console.error('Detailed email analysis failed:', error);
    return { 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    };
  }
}

function calculateCategoryScores(factors: any[]): any {
  const categories = ['HEADER', 'CONTENT', 'LINK', 'ATTACHMENT'];
  const scores: any = {
    header: null,
    content: null,
    links: null,
    attachments: null
  };

  categories.forEach(category => {
    const categoryFactors = factors.filter(f => f.category === category);
    if (categoryFactors.length > 0) {
      const maxScore = Math.max(...categoryFactors.map(f => f.score));
      const avgScore = categoryFactors.reduce((sum, f) => sum + f.score, 0) / categoryFactors.length;
      const finalScore = Math.round((maxScore + avgScore) / 2);
      
      switch(category) {
        case 'HEADER':
          scores.header = finalScore;
          break;
        case 'CONTENT':
          scores.content = finalScore;
          break;
        case 'LINK':
          scores.links = finalScore;
          break;
        case 'ATTACHMENT':
          scores.attachments = finalScore;
          break;
      }
    }
  });

  return scores;
}

function extractGeminiReasoning(factors: any[]): string {
  const geminiFactors = factors.filter(f => 
    f.description.toLowerCase().includes('ai analysis') || 
    f.description.toLowerCase().includes('gemini') ||
    f.category === 'CONTENT'
  );
  
  if (geminiFactors.length > 0) {
    return geminiFactors.map(f => f.description).join(' ');
  }
  
  return 'AI analysis not available for this email.';
}

function extractSuspiciousTextRanges(factors: any[], bodyText: string): any[] {
  const ranges: any[] = [];
  const contentFactors = factors.filter(f => f.category === 'CONTENT');
  
  // Extract suspicious keywords and phrases from content analysis
  const suspiciousKeywords = [
    'urgent', 'immediate', 'suspended', 'verify', 'confirm', 'click here',
    'limited time', 'expires', 'account', 'security', 'winner', 'congratulations'
  ];
  
  suspiciousKeywords.forEach(keyword => {
    const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
    let match;
    while ((match = regex.exec(bodyText)) !== null) {
      ranges.push({
        text: match[0],
        reason: `Suspicious keyword: "${keyword}" often used in phishing emails`,
        startIndex: match.index,
        endIndex: match.index + match[0].length
      });
    }
  });
  
  return ranges;
}

// Handle extension icon click
chrome.action.onClicked.addListener((tab) => {
  if (tab.url?.includes('mail.google.com') || 
      tab.url?.includes('outlook.live.com') || 
      tab.url?.includes('outlook.office.com')) {
    chrome.scripting.executeScript({
      target: { tabId: tab.id! },
      files: ['src/content.js']
    });
  }
});
