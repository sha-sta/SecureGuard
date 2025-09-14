import re
import json
import logging
import asyncio
from datetime import datetime

try:
    from google import genai
except ImportError:
    import google.generativeai as genai
from pydantic import BaseModel
from typing import List, Dict, Any, Optional, Literal

from ..models import RiskFactor, ContentAnalysisResult
from ..config import settings

logger = logging.getLogger(__name__)


class GeminiAnalysis(BaseModel):
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    confidence: int
    suspicious_elements: List[str]
    explanation: List[str]


class ContentAnalyzer:
    """
    Analyzes email content for phishing and scam indicators using:
    - Google Gemini AI for advanced content analysis
    - Pattern-based detection for common phishing tactics
    - Urgency and social engineering detection
    - Language anomaly detection
    """

    def __init__(self):
        # Configure Gemini AI
        if settings.GEMINI_API_KEY:
            self.model_name = "gemini-2.5-flash"
        else:
            self.model = None
            logger.warning("Gemini API key not provided - AI analysis disabled")

    async def _gemini_analysis(self, subject: str, body: str) -> List[RiskFactor]:
        """
        Use Google Gemini AI for advanced content analysis
        """
        risk_factors = []

        try:
            logger.info(f"Starting Gemini AI analysis for subject: {subject[:50]}...")

            # Configure Gemini client for structured output
            client = genai.Client(api_key=settings.GEMINI_API_KEY)

            # Enhanced prompt for structured output
            structured_prompt = f"""
            Analyze the following email content for potential phishing or scam indicators:
            
            Subject: {subject}
            Body: {body}
            
            Please provide a structured analysis with:
            1. Risk level assessment (LOW, MEDIUM, HIGH)
            2. Confidence percentage (0-100)
            3. Specific suspicious elements found (array of strings)
            4. Explanation as an array of bullet points (each string should be a complete sentence explaining one aspect)

            Focus on indicators like:
            - Urgency language ("act now", "limited time")
            - Threats ("account suspended", "verify immediately")
            - Financial requests or suspicious links
            - Brand impersonation attempts
            - Grammar and spelling inconsistencies
            - Unusual sender behavior or context

            For the explanation array, provide 2-4 bullet points that explain your analysis in simple terms.
            Each bullet point should be a complete sentence explaining one specific finding.
            
            Return a JSON array with one analysis object matching the GeminiAnalysis schema.
            """

            response = client.models.generate_content(
                model=self.model_name,
                contents=structured_prompt,
                config={
                    "response_mime_type": "application/json",
                    "response_schema": list[GeminiAnalysis],
                },
            )

            if response and response.parsed:
                # Use the parsed structured output
                gemini_analyses = response.parsed

                for analysis in gemini_analyses:
                    score = self._confidence_to_score(
                        analysis.confidence, analysis.risk_level
                    )

                    # Format explanation as bullet points
                    if isinstance(analysis.explanation, list) and analysis.explanation:
                        bullet_points = []
                        for point in analysis.explanation:
                            # Clean up the point and ensure it doesn't already start with bullet
                            clean_point = point.strip()
                            if not clean_point.startswith(
                                "•"
                            ) and not clean_point.startswith("-"):
                                bullet_points.append(f"• {clean_point}")
                            else:
                                bullet_points.append(clean_point)
                        formatted_explanation = "\n".join(bullet_points)
                    else:
                        # Fallback for non-list explanations
                        formatted_explanation = (
                            f"• {analysis.explanation}"
                            if analysis.explanation
                            else "• No specific analysis available"
                        )

                    risk_factors.append(
                        RiskFactor(
                            category="CONTENT",
                            risk=analysis.risk_level,
                            score=score,
                            description=f"\n{formatted_explanation}",
                            details=f"Confidence: {analysis.confidence}%, Elements: {', '.join(analysis.suspicious_elements[:3])}",
                        )
                    )

        except asyncio.TimeoutError:
            logger.warning("Gemini AI analysis timed out")
        except Exception as e:
            logger.error(f"Gemini AI analysis error: {str(e)}")
            # No fallback - return empty risk factors if Gemini fails

        return risk_factors

    async def analyze_content(self, subject: str, body: str) -> List[RiskFactor]:
        """
        Perform comprehensive content analysis
        """
        risk_factors = []

        try:
            # Combine subject and body for analysis
            full_content = f"Subject: {subject}\n\nBody: {body}"

            # AI-powered analysis using Gemini
            if settings.GEMINI_API_KEY:
                ai_risks = await self._gemini_analysis(subject, body)
                if ai_risks:
                    risk_factors.extend(ai_risks)

        except Exception as e:
            logger.error(f"Content analysis error: {str(e)}")
            risk_factors.append(
                RiskFactor(
                    category="CONTENT",
                    risk="MEDIUM",
                    score=40,
                    description="Content analysis failed due to technical error",
                    details=str(e),
                )
            )

        return risk_factors

    def _confidence_to_score(self, confidence: int, risk_level: str) -> int:
        """
        Convert AI confidence and risk level to numerical score
        """
        base_scores = {"LOW": 20, "MEDIUM": 50, "HIGH": 80}
        base_score = base_scores.get(risk_level, 50)

        # Adjust based on confidence
        confidence_factor = confidence / 100
        adjusted_score = int(base_score * confidence_factor)

        return max(10, min(95, adjusted_score))
