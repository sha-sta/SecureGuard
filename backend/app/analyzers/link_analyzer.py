import httpx
from typing import List, Dict, Any, Optional
import logging
from urllib.parse import urlparse

from ..models import LinkData, RiskFactor, LinkAnalysisResult
from ..config import settings

logger = logging.getLogger(__name__)


class LinkAnalyzer:
    """
    Analyzes URLs in emails using Google Web Risk Lookup API exclusively.
    Provides threat detection for malicious, phishing, and unwanted software URLs.
    """

    def __init__(self):
        self.web_risk_base_url = "https://webrisk.googleapis.com/v1"

        # Google Web Risk threat types
        self.threat_types = [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "SOCIAL_ENGINEERING_EXTENDED_COVERAGE",
        ]

        # Risk level mapping based on threat types
        self.threat_risk_mapping = {
            "MALWARE": ("HIGH", 95),
            "SOCIAL_ENGINEERING": ("HIGH", 90),
            "UNWANTED_SOFTWARE": ("MEDIUM", 70),
            "SOCIAL_ENGINEERING_EXTENDED_COVERAGE": ("HIGH", 85),
        }

    async def analyze_links(self, links: List[LinkData]) -> List[RiskFactor]:
        """
        Analyze all links in an email using Google Web Risk API
        """
        risk_factors = []

        if not settings.GOOGLE_WEB_RISK_API_KEY:
            logger.warning(
                "Google Web Risk API key not configured - link analysis disabled"
            )
            return risk_factors

        for i, link in enumerate(links):
            try:
                link_risks = await self._analyze_single_link(link, i)
                risk_factors.extend(link_risks)
            except Exception as e:
                logger.error(f"Google Web Risk analysis error for {link.url}: {str(e)}")
                risk_factors.append(
                    RiskFactor(
                        category="LINK",
                        risk="MEDIUM",
                        score=40,
                        description="Link analysis failed due to technical error",
                        details=f"Position: {i}, URL: {link.url[:100]}..., Error: {str(e)}",
                    )
                )

        return risk_factors

    async def analyze_single_url(self, url: str) -> LinkAnalysisResult:
        """
        Analyze a single URL using Google Web Risk API
        """
        result = LinkAnalysisResult(url=url, reputation_score=50)

        try:
            if not settings.GOOGLE_WEB_RISK_API_KEY:
                logger.warning("Google Web Risk API key not configured")
                result.risk_factors = ["Google Web Risk API key not configured"]
                return result

            # Check URL against Google Web Risk
            threat_info = await self._check_web_risk(url)

            if threat_info:
                result.is_malicious = True
                result.reputation_score = 5  # Very low score for detected threats
                result.risk_factors = [
                    f"Google Web Risk detected: {', '.join(threat_info['threat_types'])}"
                ]

                # Set specific flags based on threat type
                for threat_type in threat_info["threat_types"]:
                    if threat_type == "SOCIAL_ENGINEERING":
                        result.is_phishing = True
                    elif threat_type == "MALWARE":
                        result.is_malicious = True
            else:
                result.reputation_score = 90  # High score for clean URLs
                result.risk_factors = ["Google Web Risk: No threats detected"]

        except Exception as e:
            logger.error(f"Single URL analysis error: {str(e)}")
            result.risk_factors = [f"Analysis error: {str(e)}"]
            result.reputation_score = 30  # Lower score due to analysis failure

        return result

    async def _analyze_single_link(
        self, link: LinkData, position: int
    ) -> List[RiskFactor]:
        """
        Analyze a single link using Google Web Risk API
        """
        risk_factors = []
        url = link.url

        try:
            # Check URL against Google Web Risk
            threat_info = await self._check_web_risk(url)

            if threat_info:
                # Process each detected threat type
                for threat_type in threat_info["threat_types"]:
                    risk_level, score = self.threat_risk_mapping.get(
                        threat_type, ("MEDIUM", 50)
                    )

                    # Create detailed description based on threat type
                    if threat_type == "MALWARE":
                        description = "Google Web Risk detected malware threat"
                    elif threat_type == "SOCIAL_ENGINEERING":
                        description = "Google Web Risk detected phishing/social engineering threat"
                    elif threat_type == "UNWANTED_SOFTWARE":
                        description = "Google Web Risk detected unwanted software"
                    elif threat_type == "SOCIAL_ENGINEERING_EXTENDED_COVERAGE":
                        description = "Google Web Risk detected advanced social engineering threat"
                    else:
                        description = f"Google Web Risk detected threat: {threat_type}"

                    risk_factors.append(
                        RiskFactor(
                            category="LINK",
                            risk=risk_level,
                            score=score,
                            description=description,
                            details=f"Position: {position}, URL: {url[:100]}..., Threat Type: {threat_type}",
                        )
                    )

                # Add additional context if multiple threats detected
                if len(threat_info["threat_types"]) > 1:
                    risk_factors.append(
                        RiskFactor(
                            category="LINK",
                            risk="HIGH",
                            score=95,
                            description="Multiple threat types detected by Google Web Risk",
                            details=f"Position: {position}, URL: {url[:100]}..., Threats: {', '.join(threat_info['threat_types'])}",
                        )
                    )
            else:
                # URL is clean according to Google Web Risk
                logger.info(f"Google Web Risk: URL {url[:50]}... is clean")

                # Add positive risk factor for clean links so frontend can display them
                risk_factors.append(
                    RiskFactor(
                        category="LINK",
                        risk="LOW",
                        score=10,
                        description="Google Web Risk: No threats detected",
                        details=f"Position: {position}, URL: {url[:100]}..., Status: Clean",
                    )
                )

        except Exception as e:
            logger.error(f"Google Web Risk API error: {str(e)}")
            risk_factors.append(
                RiskFactor(
                    category="LINK",
                    risk="MEDIUM",
                    score=35,
                    description="Google Web Risk analysis failed - unable to verify URL safety",
                    details=f"Position: {position}, URL: {url[:100]}..., Error: {str(e)}",
                )
            )

        return risk_factors

    async def _check_web_risk(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Check URL against Google Web Risk Lookup API
        """
        try:
            api_key = settings.GOOGLE_WEB_RISK_API_KEY

            # Construct the Web Risk Lookup API URL
            lookup_url = f"{self.web_risk_base_url}/uris:search"

            # Prepare query parameters
            params = {"uri": url, "threatTypes": self.threat_types, "key": api_key}

            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(lookup_url, params=params)

                if response.status_code == 200:
                    result = response.json()
                    print(result)

                    # Check if any threats were found
                    if "threat" in result:
                        threat_info = result["threat"]
                        threat_types = threat_info.get("threatTypes", [])

                        logger.warning(
                            f"Google Web Risk threats found for {url[:50]}...: {threat_types}"
                        )

                        return {
                            "threat_types": threat_types,
                            "platform_types": threat_info.get("platformTypes", []),
                            "threat_entry_types": threat_info.get(
                                "threatEntryTypes", []
                            ),
                        }
                    else:
                        # No threats found
                        logger.info(
                            f"Google Web Risk: No threats found for {url[:50]}..."
                        )
                        return None

                elif response.status_code == 400:
                    logger.error(f"Google Web Risk API bad request: {response.text}")
                    return None

                elif response.status_code == 401:
                    logger.error(
                        "Google Web Risk API authentication failed - check API key"
                    )
                    return None

                elif response.status_code == 403:
                    logger.error(
                        "Google Web Risk API forbidden - check API key permissions"
                    )
                    return None

                else:
                    logger.warning(
                        f"Google Web Risk API error: {response.status_code} - {response.text}"
                    )
                    return None

        except Exception as e:
            logger.error(f"Google Web Risk API request error: {str(e)}")
            return None

    def get_supported_threat_types(self) -> List[str]:
        """
        Return list of supported threat types
        """
        return self.threat_types.copy()

    def explain_threat_type(self, threat_type: str) -> str:
        """
        Provide human-readable explanation of threat types
        """
        explanations = {
            "MALWARE": "The URL hosts or distributes malicious software that can harm your device",
            "SOCIAL_ENGINEERING": "The URL is designed to trick users into revealing sensitive information (phishing)",
            "UNWANTED_SOFTWARE": "The URL distributes software that may be unwanted or potentially harmful",
            "SOCIAL_ENGINEERING_EXTENDED_COVERAGE": "Advanced social engineering threat with extended detection coverage",
        }

        return explanations.get(threat_type, f"Unknown threat type: {threat_type}")
