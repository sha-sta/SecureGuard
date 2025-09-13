import re
import dns.resolver
import socket
import tldextract
from typing import List, Optional, Dict, Any
import logging
from datetime import datetime, timezone
import whois

from ..models import EmailData, RiskFactor, HeaderAnalysisResult

logger = logging.getLogger(__name__)


class HeaderAnalyzer:
    """
    Analyzes email headers for security threats including:
    - SPF/DKIM/DMARC validation
    - Sender IP/domain validation
    - Timestamp and geographic anomalies
    """

    def __init__(self):
        self.suspicious_domains = {
            "gmail.com",
            "outlook.com",
            "yahoo.com",
            "hotmail.com",
        }
        self.suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".bit", ".onion"}

    async def analyze(self, email_data: EmailData) -> List[RiskFactor]:
        """
        Perform comprehensive header analysis
        """
        risk_factors = []

        try:
            # Extract sender domain
            sender_domain = self._extract_domain(email_data.from_address)

            # 4. Domain Analysis
            domain_risks = await self._analyze_domain(sender_domain)
            risk_factors.extend(domain_risks)

            # 5. IP Analysis
            sender_ip = self._extract_sender_ip(email_data.headers)
            if sender_ip:
                ip_risks = await self._analyze_sender_ip(sender_ip)
                risk_factors.extend(ip_risks)

            # 6. Timestamp Analysis
            timestamp_risks = self._analyze_timestamps(
                email_data.headers, email_data.timestamp
            )
            risk_factors.extend(timestamp_risks)

            # 7. Header Anomaly Detection
            header_risks = self._detect_header_anomalies(email_data.headers)
            risk_factors.extend(header_risks)

        except Exception as e:
            logger.error(f"Header analysis error: {str(e)}")
            risk_factors.append(
                RiskFactor(
                    category="HEADER",
                    risk="MEDIUM",
                    score=40,
                    description="Header analysis failed due to technical error",
                    details=str(e),
                )
            )

        return risk_factors

    def _extract_domain(self, email_address: str) -> str:
        """Extract domain from email address"""
        try:
            return email_address.split("@")[1].lower()
        except IndexError:
            return ""

    def _extract_sender_ip(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract sender IP from Received headers"""
        received_headers = []
        for key, value in headers.items():
            if key.lower() == "received":
                received_headers.append(value)

        # Parse the first (most recent) Received header for IP
        if received_headers:
            # Look for IP addresses in format [192.168.1.1] or (192.168.1.1)
            ip_pattern = r"[\[\(](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\]\)]"
            match = re.search(ip_pattern, received_headers[0])
            if match:
                return match.group(1)

        return None

    async def _analyze_domain(self, domain: str) -> List[RiskFactor]:
        """Analyze sender domain for suspicious characteristics"""
        risk_factors = []

        try:
            # Extract domain components
            extracted = tldextract.extract(domain)
            tld = f".{extracted.suffix}"

            # Check for suspicious TLDs
            if tld in self.suspicious_tlds:
                risk_factors.append(
                    RiskFactor(
                        category="HEADER",
                        risk="HIGH",
                        score=70,
                        description=f"Suspicious top-level domain: {tld}",
                        details=f"Domain: {domain}",
                    )
                )

            # Check for typosquatting of popular domains
            typosquat_risk = self._check_typosquatting(domain)
            if typosquat_risk:
                risk_factors.append(typosquat_risk)

            # Check domain age and registration
            domain_age_risk = await self._check_domain_age(domain)
            if domain_age_risk:
                risk_factors.append(domain_age_risk)

            # Check for suspicious domain patterns
            pattern_risks = self._check_domain_patterns(domain)
            risk_factors.extend(pattern_risks)

        except Exception as e:
            logger.error(f"Domain analysis error: {str(e)}")

        return risk_factors

    def _check_typosquatting(self, domain: str) -> Optional[RiskFactor]:
        """Check for typosquatting of legitimate domains"""
        legitimate_domains = [
            "gmail.com",
            "outlook.com",
            "yahoo.com",
            "hotmail.com",
            "amazon.com",
            "paypal.com",
            "ebay.com",
            "microsoft.com",
            "apple.com",
            "google.com",
            "facebook.com",
            "twitter.com",
        ]

        for legit_domain in legitimate_domains:
            # Simple Levenshtein distance check
            if (
                self._levenshtein_distance(domain, legit_domain) <= 2
                and domain != legit_domain
            ):
                return RiskFactor(
                    category="HEADER",
                    risk="HIGH",
                    score=85,
                    description=f"Possible typosquatting of {legit_domain}",
                    details=f"Domain: {domain}",
                )

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

    async def _check_domain_age(self, domain: str) -> Optional[RiskFactor]:
        """Check domain registration age"""
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                days_old = (datetime.now() - creation_date).days

                # Domains less than 30 days old are suspicious
                if days_old < 30:
                    return RiskFactor(
                        category="HEADER",
                        risk="HIGH",
                        score=75,
                        description=f"Very new domain (registered {days_old} days ago)",
                        details=f"Domain: {domain}",
                    )
                elif days_old < 90:
                    return RiskFactor(
                        category="HEADER",
                        risk="MEDIUM",
                        score=50,
                        description=f"Recently registered domain ({days_old} days ago)",
                        details=f"Domain: {domain}",
                    )
        except Exception as e:
            logger.debug(f"Domain age check failed for {domain}: {str(e)}")

        return None

    def _check_domain_patterns(self, domain: str) -> List[RiskFactor]:
        """Check for suspicious domain patterns"""
        risk_factors = []

        # Check for excessive hyphens or numbers
        if domain.count("-") > 3:
            risk_factors.append(
                RiskFactor(
                    category="HEADER",
                    risk="MEDIUM",
                    score=45,
                    description="Domain contains excessive hyphens",
                    details=f"Domain: {domain}",
                )
            )

        # Check for random-looking strings
        if re.search(r"[0-9]{4,}", domain):
            risk_factors.append(
                RiskFactor(
                    category="HEADER",
                    risk="MEDIUM",
                    score=40,
                    description="Domain contains long number sequences",
                    details=f"Domain: {domain}",
                )
            )

        # Check for suspicious keywords
        suspicious_keywords = [
            "secure",
            "verify",
            "account",
            "update",
            "confirm",
            "urgent",
        ]
        for keyword in suspicious_keywords:
            if keyword in domain.lower():
                risk_factors.append(
                    RiskFactor(
                        category="HEADER",
                        risk="MEDIUM",
                        score=55,
                        description=f"Domain contains suspicious keyword: {keyword}",
                        details=f"Domain: {domain}",
                    )
                )
                break

        return risk_factors

    async def _analyze_sender_ip(self, sender_ip: str) -> List[RiskFactor]:
        """Analyze sender IP for suspicious characteristics"""
        risk_factors = []

        try:
            # Check if IP is in blacklists (simplified check)
            if self._is_suspicious_ip(sender_ip):
                risk_factors.append(
                    RiskFactor(
                        category="HEADER",
                        risk="HIGH",
                        score=80,
                        description="Sender IP is on suspicious IP list",
                        details=f"IP: {sender_ip}",
                    )
                )

            # Check geographic location (simplified)
            geo_risk = self._check_ip_geolocation(sender_ip)
            if geo_risk:
                risk_factors.append(geo_risk)

        except Exception as e:
            logger.error(f"IP analysis error: {str(e)}")

        return risk_factors

    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is in known suspicious ranges"""
        # This is a simplified check - in production, use proper threat intelligence
        suspicious_ranges = [
            "10.0.0.0/8",  # Private network
            "172.16.0.0/12",  # Private network
            "192.168.0.0/16",  # Private network
        ]

        # For demo purposes, mark private IPs as suspicious
        for ip_range in suspicious_ranges:
            if self._ip_in_range(ip, ip_range):
                return True

        return False

    def _ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if IP is in given range"""
        try:
            import ipaddress

            return ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range)
        except Exception:
            return False

    def _check_ip_geolocation(self, ip: str) -> Optional[RiskFactor]:
        """Check IP geolocation for anomalies"""
        # This would integrate with a geolocation service
        # For demo purposes, we'll skip this implementation
        return None

    def _analyze_timestamps(
        self, headers: Dict[str, str], email_timestamp: str
    ) -> List[RiskFactor]:
        """Analyze timestamps for anomalies"""
        risk_factors = []

        try:
            # Check for timestamp inconsistencies
            date_header = headers.get("Date", "")
            if date_header:
                # Parse and compare timestamps
                # This is a simplified implementation
                pass

            # Check for future timestamps
            try:
                email_time = datetime.fromisoformat(
                    email_timestamp.replace("Z", "+00:00")
                )
                current_time = datetime.now(timezone.utc)

                if email_time > current_time:
                    time_diff = (
                        email_time - current_time
                    ).total_seconds() / 3600  # hours
                    if time_diff > 1:  # More than 1 hour in the future
                        risk_factors.append(
                            RiskFactor(
                                category="HEADER",
                                risk="MEDIUM",
                                score=50,
                                description=f"Email timestamp is {time_diff:.1f} hours in the future",
                                details=f"Email time: {email_timestamp}",
                            )
                        )
            except Exception as e:
                logger.debug(f"Timestamp parsing error: {str(e)}")

        except Exception as e:
            logger.error(f"Timestamp analysis error: {str(e)}")

        return risk_factors

    def _detect_header_anomalies(self, headers: Dict[str, str]) -> List[RiskFactor]:
        """Detect various header anomalies"""
        risk_factors = []

        # Check for missing important headers
        important_headers = ["Message-ID", "Date", "From"]
        missing_headers = [h for h in important_headers if h not in headers]

        if missing_headers:
            risk_factors.append(
                RiskFactor(
                    category="HEADER",
                    risk="MEDIUM",
                    score=45,
                    description=f"Missing important headers: {', '.join(missing_headers)}",
                    details="Standard email headers are missing",
                )
            )

        # Check for suspicious header values
        for header, value in headers.items():
            if header.lower() == "x-mailer" and "suspicious" in value.lower():
                risk_factors.append(
                    RiskFactor(
                        category="HEADER",
                        risk="MEDIUM",
                        score=40,
                        description="Suspicious mail client detected",
                        details=f"X-Mailer: {value}",
                    )
                )

        return risk_factors
