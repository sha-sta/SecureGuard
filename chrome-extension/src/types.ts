// Type definitions for the SecureGuard extension

export interface EmailData {
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

export interface LinkData {
  url: string;
  displayText: string;
  position: number;
}

export interface AttachmentData {
  filename: string;
  mimeType: string;
  size: number;
  hash?: string;
}

export interface RiskScore {
  overall: 'LOW' | 'MEDIUM' | 'HIGH';
  score: number; // 0-100
  factors: RiskFactor[];
  explanation: string;
}

export interface RiskFactor {
  category: 'HEADER' | 'LINK' | 'ATTACHMENT' | 'CONTENT';
  risk: 'LOW' | 'MEDIUM' | 'HIGH';
  score: number;
  description: string;
  details?: string;
}

export interface ApiResponse {
  success: boolean;
  riskScore?: RiskScore;
  error?: string;
}

export interface WebmailProvider {
  name: 'gmail' | 'outlook';
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
