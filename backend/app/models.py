from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Literal
from datetime import datetime


class LinkData(BaseModel):
    url: str
    displayText: str
    position: int


class AttachmentData(BaseModel):
    filename: str
    mimeType: str
    size: int
    hash: Optional[str] = None


class EmailData(BaseModel):
    from_address: str = Field(..., alias="from")
    to: List[str]
    subject: str
    body: str
    headers: Dict[str, str] = {}
    links: List[LinkData] = []
    attachments: List[AttachmentData] = []
    timestamp: str
    messageId: str

    class Config:
        populate_by_name = True


class RiskFactor(BaseModel):
    category: Literal["HEADER", "LINK", "ATTACHMENT", "CONTENT"]
    risk: Literal["LOW", "MEDIUM", "HIGH"]
    score: int = Field(..., ge=0, le=100)
    description: str
    details: Optional[str] = None


class RiskScore(BaseModel):
    overall: Literal["LOW", "MEDIUM", "HIGH"]
    score: int = Field(..., ge=0, le=100)
    factors: List[RiskFactor]
    explanation: str


class AnalysisResponse(BaseModel):
    success: bool
    riskScore: Optional[RiskScore] = None
    error: Optional[str] = None
    processingTime: Optional[float] = None


class HeaderAnalysisResult(BaseModel):
    spf_status: Literal["PASS", "FAIL", "NEUTRAL", "UNKNOWN"]
    dkim_status: Literal["PASS", "FAIL", "UNKNOWN"]
    dmarc_status: Literal["PASS", "FAIL", "UNKNOWN"]
    sender_ip: Optional[str] = None
    sender_domain: str
    is_suspicious_domain: bool = False
    geographic_anomaly: bool = False
    timestamp_anomaly: bool = False
    risk_factors: List[str] = []


class LinkAnalysisResult(BaseModel):
    url: str
    is_malicious: bool = False
    is_phishing: bool = False
    is_typosquatting: bool = False
    reputation_score: int = Field(..., ge=0, le=100)
    redirects_to: Optional[str] = None
    risk_factors: List[str] = []


class AttachmentAnalysisResult(BaseModel):
    filename: str
    is_malicious: bool = False
    has_macros: bool = False
    has_javascript: bool = False
    has_suspicious_extension: bool = False
    hash_reputation: Literal["CLEAN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"] = "UNKNOWN"
    risk_factors: List[str] = []


class ContentAnalysisResult(BaseModel):
    is_phishing: bool = False
    phishing_confidence: float = Field(..., ge=0.0, le=1.0)
    suspicious_patterns: List[str] = []
    language_anomalies: List[str] = []
    urgency_indicators: List[str] = []
    social_engineering_tactics: List[str] = []
