import re
import httpx
import tldextract
from typing import List, Dict, Any, Optional
import logging
import asyncio
from urllib.parse import urlparse, unquote
import hashlib
import base64

from ..models import LinkData, RiskFactor, LinkAnalysisResult
from ..config import settings

logger = logging.getLogger(__name__)


class LinkAnalyzer:
    """
    Analyzes URLs in emails for security threats including:
    - URL reputation checks (Google Safe Browsing, VirusTotal)
    - Static parsing for typosquatting and obfuscation
    - Redirect chain analysis
    - Suspicious pattern detection
    """

    def __init__(self):
        self.suspicious_tlds = {
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".bit",
            ".onion",
            ".click",
            ".download",
            ".work",
            ".men",
            ".top",
            ".stream",
        }

        self.url_shorteners = {
            "bit.ly",
            "tinyurl.com",
            "goo.gl",
            "t.co",
            "ow.ly",
            "buff.ly",
            "is.gd",
            "tiny.cc",
            "short.link",
        }

        self.legitimate_domains = {
            "google.com",
            "microsoft.com",
            "apple.com",
            "amazon.com",
            "paypal.com",
            "ebay.com",
            "facebook.com",
            "twitter.com",
            "linkedin.com",
            "github.com",
            "stackoverflow.com",
        }

        self.phishing_keywords = [
            "verify",
            "suspend",
            "urgent",
            "confirm",
            "update",
            "secure",
            "account",
            "login",
            "signin",
            "click",
            "winner",
            "congratulations",
            "limited",
            "expires",
            "act-now",
            "immediate",
        ]

    async def analyze_links(self, links: List[LinkData]) -> List[RiskFactor]:
        """
        Analyze all links in an email
        """
        risk_factors = []

        for i, link in enumerate(links):
            try:
                link_risks = await self._analyze_single_link(link, i)
                risk_factors.extend(link_risks)
            except Exception as e:
                logger.error(f"Link analysis error for {link.url}: {str(e)}")
                risk_factors.append(
                    RiskFactor(
                        category="LINK",
                        risk="MEDIUM",
                        score=40,
                        description="Link analysis failed due to technical error",
                        details=f"URL: {link.url}, Error: {str(e)}",
                    )
                )

        return risk_factors

    async def analyze_single_url(self, url: str) -> LinkAnalysisResult:
        """
        Analyze a single URL and return detailed results
        """
        result = LinkAnalysisResult(url=url, reputation_score=50)

        try:
            # Static analysis
            static_risks = await self._static_url_analysis(url)

            # Reputation checks
            reputation_score = await self._check_url_reputation(url)
            result.reputation_score = reputation_score

            # Determine if malicious based on various factors
            if reputation_score < 30:
                result.is_malicious = True
            elif any("phishing" in risk.lower() for risk in static_risks):
                result.is_phishing = True
            elif any("typosquat" in risk.lower() for risk in static_risks):
                result.is_typosquatting = True

            result.risk_factors = static_risks

        except Exception as e:
            logger.error(f"Single URL analysis error: {str(e)}")
            result.risk_factors.append(f"Analysis error: {str(e)}")

        return result

    async def _analyze_single_link(
        self, link: LinkData, position: int
    ) -> List[RiskFactor]:
        """
        Analyze a single link for threats
        """
        risk_factors = []
        url = link.url

        # 1. Static URL analysis
        static_risks = await self._static_url_analysis(url)
        for risk_desc in static_risks:
            risk_level = self._determine_risk_level(risk_desc)
            score = self._calculate_risk_score(risk_desc, risk_level)

            risk_factors.append(
                RiskFactor(
                    category="LINK",
                    risk=risk_level,
                    score=score,
                    description=risk_desc,
                    details=f"Position: {position}, URL: {url[:100]}...",
                )
            )

        # 2. URL reputation check
        reputation_score = await self._check_url_reputation(url)
        if reputation_score < 50:
            risk_level = "HIGH" if reputation_score < 30 else "MEDIUM"
            risk_factors.append(
                RiskFactor(
                    category="LINK",
                    risk=risk_level,
                    score=100 - reputation_score,
                    description=f"Low URL reputation score: {reputation_score}/100",
                    details=f"URL: {url}",
                )
            )

        # 3. Display text vs URL mismatch
        mismatch_risk = self._check_display_mismatch(link)
        if mismatch_risk:
            risk_factors.append(mismatch_risk)

        # 4. Redirect analysis
        redirect_risks = await self._analyze_redirects(url)
        risk_factors.extend(redirect_risks)

        return risk_factors

    async def _static_url_analysis(self, url: str) -> List[str]:
        """
        Perform static analysis of URL structure
        """
        risks = []

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()

            # Extract domain components
            extracted = tldextract.extract(domain)
            tld = f".{extracted.suffix}" if extracted.suffix else ""

            # 1. Check for suspicious TLDs
            if tld in self.suspicious_tlds:
                risks.append(f"Suspicious top-level domain: {tld}")

            # 2. Check for typosquatting
            typosquat_domain = self._check_domain_typosquatting(domain)
            if typosquat_domain:
                risks.append(f"Possible typosquatting of {typosquat_domain}")

            # 3. Check for URL shorteners
            if any(shortener in domain for shortener in self.url_shorteners):
                risks.append("URL shortener detected - destination unknown")

            # 6. Check for IP addresses instead of domains
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                risks.append("URL uses IP address instead of domain name")

            # 7. Check for suspicious query parameters
            if any(keyword in query for keyword in ["redirect", "url", "goto", "link"]):
                risks.append("Suspicious redirect parameters detected")

            # 8. Check for excessive subdomain levels
            if domain.count(".") > 3:
                risks.append("Excessive subdomain levels detected")

            # 9. Check for homograph attacks
            if self._contains_homographs(domain):
                risks.append("Domain contains potential homograph characters")

            # 10. Check for suspicious port numbers
            if (
                ":" in domain
                and not domain.endswith(":80")
                and not domain.endswith(":443")
            ):
                risks.append("Non-standard port number detected")

        except Exception as e:
            logger.error(f"Static URL analysis error: {str(e)}")
            risks.append(f"URL parsing error: {str(e)}")

        return risks

    def _check_domain_typosquatting(self, domain: str) -> Optional[str]:
        """
        Check if domain is typosquatting a legitimate domain
        """
        for legit_domain in self.legitimate_domains:
            if (
                self._levenshtein_distance(domain, legit_domain) <= 2
                and domain != legit_domain
            ):
                return legit_domain
        return None

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _is_base64(self, s: str) -> bool:
        """Check if string is base64 encoded"""
        try:
            if len(s) % 4 == 0:
                base64.b64decode(s, validate=True)
                return True
        except Exception:
            pass
        return False

    def _contains_homographs(self, domain: str) -> bool:
        """
        Check for homograph attacks (lookalike characters)
        """
        # Common homograph characters
        homographs = {
            "а": "a",
            "е": "e",
            "о": "o",
            "р": "p",
            "с": "c",
            "х": "x",
            "у": "y",
            "А": "A",
            "В": "B",
            "Е": "E",
            "К": "K",
            "М": "M",
            "Н": "H",
            "О": "O",
            "Р": "P",
            "С": "C",
            "Т": "T",
            "У": "Y",
            "Х": "X",
        }

        return any(char in domain for char in homographs.keys())

    async def _check_url_reputation(self, url: str) -> int:
        """
        Check URL reputation using various services
        Returns score from 0-100 (higher is safer)
        """
        reputation_score = 50  # Default neutral score

        try:
            # 1. Google Safe Browsing API
            if settings.GOOGLE_SAFE_BROWSING_API_KEY:
                gsb_score = await self._check_google_safe_browsing(url)
                reputation_score = min(reputation_score, gsb_score)

            # 2. VirusTotal API
            if settings.VIRUSTOTAL_API_KEY:
                vt_score = await self._check_virustotal(url)
                reputation_score = min(reputation_score, vt_score)

        except Exception as e:
            logger.error(f"URL reputation check error: {str(e)}")
            reputation_score = 40  # Lower score due to check failure

        return reputation_score

    async def _check_google_safe_browsing(self, url: str) -> int:
        """
        Check URL against Google Safe Browsing API
        """
        try:
            api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

            payload = {
                "client": {"clientId": "secureguard", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(api_url, json=payload)

                if response.status_code == 200:
                    result = response.json()
                    if result.get("matches"):
                        return 10  # Very low score for detected threats
                    return 90  # High score for clean URLs
                else:
                    logger.warning(
                        f"Google Safe Browsing API error: {response.status_code}"
                    )
                    return 50  # Neutral score on API error

        except Exception as e:
            logger.error(f"Google Safe Browsing check error: {str(e)}")
            return 50

    async def _check_virustotal(self, url: str) -> int:
        """
        Check URL against VirusTotal API using URL scanning
        """
        try:
            api_key = settings.VIRUSTOTAL_API_KEY

            # First, submit URL for scanning
            scan_result = await self._submit_url_to_virustotal(url, api_key)
            if not scan_result:
                return 50

            # Get the analysis ID from scan result
            analysis_id = scan_result.get("data", {}).get("id")
            if not analysis_id:
                return 50

            # Wait a moment for analysis to complete
            await asyncio.sleep(2)

            # Get analysis results
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            headers = {"x-apikey": api_key}

            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(analysis_url, headers=headers)

                if response.status_code == 200:
                    result = response.json()
                    attributes = result.get("data", {}).get("attributes", {})
                    stats = attributes.get("stats", {})

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected

                    if total > 0:
                        # Calculate threat ratio
                        threat_ratio = (malicious + suspicious) / total
                        score = max(10, int(100 * (1 - threat_ratio)))

                        logger.info(
                            f"VirusTotal URL scan: {malicious} malicious, {suspicious} suspicious out of {total} engines"
                        )
                        return score

                    return 70  # Default good score if no analysis available
                else:
                    logger.warning(
                        f"VirusTotal analysis API error: {response.status_code}"
                    )
                    return 50

        except Exception as e:
            logger.error(f"VirusTotal URL check error: {str(e)}")
            return 50

    async def _submit_url_to_virustotal(self, url: str, api_key: str) -> dict:
        """
        Submit URL to VirusTotal for scanning
        """
        try:
            scan_url = "https://www.virustotal.com/api/v3/urls"
            headers = {"x-apikey": api_key}
            data = {"url": url}

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(scan_url, headers=headers, data=data)

                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warning(
                        f"VirusTotal URL submission error: {response.status_code}"
                    )
                    return {}

        except Exception as e:
            logger.error(f"VirusTotal URL submission error: {str(e)}")
            return {}

    def _check_display_mismatch(self, link: LinkData) -> Optional[RiskFactor]:
        """
        Check if display text mismatches the actual URL
        """
        display_text = link.displayText.lower().strip()
        actual_url = link.url.lower()

        # Skip if display text is empty or just the URL
        if not display_text or display_text == actual_url:
            return None

        # Check if display text looks like a URL but doesn't match
        if "http" in display_text or any(
            tld in display_text for tld in [".com", ".org", ".net", ".gov"]
        ):
            parsed_display = urlparse(
                display_text
                if display_text.startswith("http")
                else f"http://{display_text}"
            )
            parsed_actual = urlparse(actual_url)

            if parsed_display.netloc and parsed_actual.netloc:
                if parsed_display.netloc != parsed_actual.netloc:
                    return RiskFactor(
                        category="LINK",
                        risk="HIGH",
                        score=75,
                        description="Display text URL doesn't match actual destination",
                        details=f"Display: {display_text}, Actual: {link.url}",
                    )

        return None

    async def _analyze_redirects(self, url: str) -> List[RiskFactor]:
        """
        Analyze redirect chains for suspicious behavior
        """
        risk_factors = []

        try:
            redirect_chain = await self._follow_redirects(url)

            if len(redirect_chain) > 3:
                risk_factors.append(
                    RiskFactor(
                        category="LINK",
                        risk="MEDIUM",
                        score=50,
                        description=f"Excessive redirects detected ({len(redirect_chain)} hops)",
                        details=f"Chain: {' -> '.join(redirect_chain[:3])}...",
                    )
                )

            # Check if redirect chain goes through suspicious domains
            for redirect_url in redirect_chain[1:]:  # Skip original URL
                parsed = urlparse(redirect_url)
                domain = parsed.netloc.lower()

                # Check if any redirect goes through URL shorteners
                if any(shortener in domain for shortener in self.url_shorteners):
                    risk_factors.append(
                        RiskFactor(
                            category="LINK",
                            risk="MEDIUM",
                            score=45,
                            description="Redirect through URL shortener",
                            details=f"Shortener: {domain}",
                        )
                    )

                # Check for suspicious TLD in redirect chain
                extracted = tldextract.extract(domain)
                tld = f".{extracted.suffix}" if extracted.suffix else ""
                if tld in self.suspicious_tlds:
                    risk_factors.append(
                        RiskFactor(
                            category="LINK",
                            risk="HIGH",
                            score=70,
                            description=f"Redirect to suspicious TLD: {tld}",
                            details=f"Redirect URL: {redirect_url}",
                        )
                    )

        except Exception as e:
            logger.error(f"Redirect analysis error: {str(e)}")

        return risk_factors

    async def _follow_redirects(self, url: str, max_redirects: int = 5) -> List[str]:
        """
        Follow redirect chain and return all URLs in the chain
        """
        redirect_chain = [url]

        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=False
            ) as client:
                current_url = url

                for _ in range(max_redirects):
                    response = await client.head(current_url)

                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get("location")
                        if location:
                            # Handle relative redirects
                            if location.startswith("/"):
                                parsed = urlparse(current_url)
                                location = (
                                    f"{parsed.scheme}://{parsed.netloc}{location}"
                                )

                            redirect_chain.append(location)
                            current_url = location
                        else:
                            break
                    else:
                        break

        except Exception as e:
            logger.debug(f"Redirect following error: {str(e)}")

        return redirect_chain

    def _determine_risk_level(self, risk_description: str) -> str:
        """
        Determine risk level based on description
        """
        high_risk_patterns = [
            "typosquat",
            "malicious",
            "phishing",
            "ip address",
            "obfuscated",
            "suspicious tld",
            "homograph",
        ]

        medium_risk_patterns = [
            "shortener",
            "redirect",
            "suspicious",
            "excessive",
            "non-standard",
        ]

        risk_desc_lower = risk_description.lower()

        if any(pattern in risk_desc_lower for pattern in high_risk_patterns):
            return "HIGH"
        elif any(pattern in risk_desc_lower for pattern in medium_risk_patterns):
            return "MEDIUM"
        else:
            return "LOW"

    def _calculate_risk_score(self, risk_description: str, risk_level: str) -> int:
        """
        Calculate numerical risk score based on description and level
        """
        base_scores = {"LOW": 25, "MEDIUM": 50, "HIGH": 75}
        base_score = base_scores.get(risk_level, 50)

        # Adjust based on specific risk types
        risk_desc_lower = risk_description.lower()

        if "typosquat" in risk_desc_lower or "phishing" in risk_desc_lower:
            return min(90, base_score + 15)
        elif "malicious" in risk_desc_lower:
            return min(95, base_score + 20)
        elif "obfuscated" in risk_desc_lower:
            return min(85, base_score + 10)

        return base_score
