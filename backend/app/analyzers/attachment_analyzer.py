import re
import hashlib
from typing import List, Dict, Any, Optional
import logging
import httpx
import base64
import json

from ..models import AttachmentData, RiskFactor, AttachmentAnalysisResult
from ..config import settings

logger = logging.getLogger(__name__)


class AttachmentAnalyzer:
    """
    Analyzes email attachments using Sophos API for static file analysis.
    Provides comprehensive threat detection including malware, suspicious files,
    and potentially unwanted applications (PUAs).
    """

    def __init__(self):
        self.sophos_base_url = "https://de.api.labs.sophos.com"
        self.dangerous_extensions = {
            ".exe",
            ".scr",
            ".bat",
            ".cmd",
            ".com",
            ".pif",
            ".vbs",
            ".vbe",
            ".js",
            ".jse",
            ".jar",
            ".wsf",
            ".wsh",
            ".ps1",
            ".ps2",
            ".psc1",
            ".psc2",
            ".msh",
            ".msh1",
            ".msh2",
            ".mshxml",
            ".msh1xml",
            ".msh2xml",
        }

        # Sophos threat levels mapping
        self.sophos_threat_mapping = {
            "MALWARE": ("HIGH", 95),
            "PUA": ("MEDIUM", 65),
            "SUSPICIOUS": ("MEDIUM", 55),
            "CLEAN": ("LOW", 10),
            "UNKNOWN": ("MEDIUM", 30),
        }

    async def analyze_attachments(
        self, attachments: List[AttachmentData]
    ) -> List[RiskFactor]:
        """
        Analyze all attachments in an email using Sophos API
        """
        risk_factors = []

        for i, attachment in enumerate(attachments):
            try:
                attachment_risks = await self._analyze_single_attachment_data(
                    attachment, i
                )
                risk_factors.extend(attachment_risks)
            except Exception as e:
                logger.error(
                    f"Sophos attachment analysis error for {attachment.filename}: {str(e)}"
                )
                risk_factors.append(
                    RiskFactor(
                        category="ATTACHMENT",
                        risk="MEDIUM",
                        score=40,
                        description="Attachment analysis failed due to technical error",
                        details=f"File: {attachment.filename}, Error: {str(e)}",
                    )
                )

        return risk_factors

    async def analyze_single_attachment(
        self, filename: str, file_hash: Optional[str] = None
    ) -> AttachmentAnalysisResult:
        """
        Analyze a single attachment and return detailed results using Sophos API
        """
        result = AttachmentAnalysisResult(filename=filename)

        try:
            # Basic filename analysis
            static_risks = self._static_filename_analysis(filename)
            result.risk_factors.extend(static_risks)

            # Sophos API analysis if hash is available
            if file_hash:
                sophos_result = await self._check_sophos_reputation(file_hash, filename)
                if sophos_result:
                    threat_level = sophos_result.get("threat_level", "UNKNOWN")

                    if threat_level == "MALWARE":
                        result.is_malicious = True
                    elif threat_level in ["PUA", "SUSPICIOUS"]:
                        result.is_malicious = True  # Err on side of caution

                    result.hash_reputation = threat_level

            # Check for dangerous extensions
            if any(ext in filename.lower() for ext in self.dangerous_extensions):
                result.has_suspicious_extension = True

        except Exception as e:
            logger.error(f"Single attachment analysis error: {str(e)}")
            result.risk_factors.append(f"Analysis error: {str(e)}")

        return result

    async def _analyze_single_attachment_data(
        self, attachment: AttachmentData, position: int
    ) -> List[RiskFactor]:
        """
        Analyze a single attachment using Sophos API
        """
        risk_factors = []
        filename = attachment.filename

        # 1. Basic filename analysis
        filename_risks = self._static_filename_analysis(filename)
        for risk_desc in filename_risks:
            risk_level = self._determine_risk_level(risk_desc)
            score = self._calculate_risk_score(risk_desc, risk_level)

            risk_factors.append(
                RiskFactor(
                    category="ATTACHMENT",
                    risk=risk_level,
                    score=score,
                    description=risk_desc,
                    details=f"Position: {position}, File: {filename}",
                )
            )

        # 2. Sophos API analysis
        if (
            attachment.hash
            and hasattr(settings, "SOPHOS_AUTH_TOKEN")
            and settings.SOPHOS_AUTH_TOKEN
        ):
            sophos_risks = await self._analyze_with_sophos(
                attachment.hash, filename, position
            )
            risk_factors.extend(sophos_risks)
        elif attachment.hash:
            # Fallback hash analysis without Sophos
            hash_risks = await self._analyze_file_hash_basic(
                attachment.hash, filename, position
            )
            risk_factors.extend(hash_risks)
        else:
            # No hash provided
            risk_factors.append(
                RiskFactor(
                    category="ATTACHMENT",
                    risk="MEDIUM",
                    score=35,
                    description="No file hash provided for malware scanning",
                    details=f"File: {filename} - Cannot verify against threat databases",
                )
            )

        # 3. MIME type validation
        mime_risks = self._validate_mime_type(attachment, position)
        risk_factors.extend(mime_risks)

        # 4. File size analysis
        size_risks = self._analyze_file_size(attachment, position)
        risk_factors.extend(size_risks)

        return risk_factors

    async def _analyze_with_sophos(
        self, file_hash: str, filename: str, position: int
    ) -> List[RiskFactor]:
        """
        Analyze file hash using Sophos API
        """
        risk_factors = []

        try:
            sophos_result = await self._check_sophos_reputation(file_hash, filename)

            if sophos_result:
                threat_level = sophos_result.get("threat_level", "UNKNOWN")
                threat_name = sophos_result.get("threat_name", "")
                detection_name = sophos_result.get("detection_name", "")

                risk_level, score = self.sophos_threat_mapping.get(
                    threat_level, ("MEDIUM", 50)
                )

                if threat_level == "MALWARE":
                    description = (
                        f"Sophos detected malware: {threat_name or detection_name}"
                    )
                    risk_factors.append(
                        RiskFactor(
                            category="ATTACHMENT",
                            risk=risk_level,
                            score=score,
                            description=description,
                            details=f"Position: {position}, File: {filename}, Hash: {file_hash[:16]}...",
                        )
                    )
                elif threat_level == "PUA":
                    description = f"Sophos detected potentially unwanted application: {threat_name or detection_name}"
                    risk_factors.append(
                        RiskFactor(
                            category="ATTACHMENT",
                            risk=risk_level,
                            score=score,
                            description=description,
                            details=f"Position: {position}, File: {filename}",
                        )
                    )
                elif threat_level == "SUSPICIOUS":
                    description = f"Sophos flagged file as suspicious: {detection_name or 'Generic detection'}"
                    risk_factors.append(
                        RiskFactor(
                            category="ATTACHMENT",
                            risk=risk_level,
                            score=score,
                            description=description,
                            details=f"Position: {position}, File: {filename}",
                        )
                    )
                elif threat_level == "CLEAN":
                    logger.info(f"Sophos analysis: {filename} is clean")
                    # Don't add a risk factor for clean files
                else:
                    # UNKNOWN or other status
                    risk_factors.append(
                        RiskFactor(
                            category="ATTACHMENT",
                            risk="LOW",
                            score=20,
                            description="File not found in Sophos threat database",
                            details=f"Position: {position}, File: {filename}",
                        )
                    )

        except Exception as e:
            logger.error(f"Sophos API analysis error: {str(e)}")
            risk_factors.append(
                RiskFactor(
                    category="ATTACHMENT",
                    risk="MEDIUM",
                    score=40,
                    description="Sophos analysis failed - unable to verify file safety",
                    details=f"Position: {position}, File: {filename}, Error: {str(e)}",
                )
            )

        return risk_factors

    async def _check_sophos_reputation(
        self, file_hash: str, filename: str
    ) -> Optional[Dict[str, Any]]:
        """
        Check file hash against Sophos API
        """
        try:
            if (
                not hasattr(settings, "SOPHOS_AUTH_TOKEN")
                or not settings.SOPHOS_AUTH_TOKEN
            ):
                logger.warning("Sophos API key not configured")
                return None

            # Sophos Intelix API endpoint for file reputation
            api_url = f"{self.sophos_base_url}/lookup/files/v1/{file_hash}"

            headers = {
                "Authorization": f"Bearer {settings.SOPHOS_AUTH_TOKEN}",
                "Content-Type": "application/json",
            }

            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(api_url, headers=headers)

                if response.status_code == 200:
                    result = response.json()

                    # Parse Sophos response
                    reputation_data = result.get("reputationScore", {})
                    detection_data = result.get("detectionName", "")

                    # Determine threat level based on Sophos response
                    reputation_score = reputation_data.get("score", 0)
                    category = reputation_data.get("category", "")

                    if category == "MALWARE" or reputation_score >= 80:
                        threat_level = "MALWARE"
                    elif category == "PUA" or reputation_score >= 60:
                        threat_level = "PUA"
                    elif reputation_score >= 40:
                        threat_level = "SUSPICIOUS"
                    elif reputation_score < 20:
                        threat_level = "CLEAN"
                    else:
                        threat_level = "UNKNOWN"

                    logger.info(
                        f"Sophos analysis for {filename}: {threat_level} (score: {reputation_score})"
                    )

                    return {
                        "threat_level": threat_level,
                        "threat_name": category,
                        "detection_name": detection_data,
                        "reputation_score": reputation_score,
                    }

                elif response.status_code == 404:
                    logger.info(
                        f"File hash {file_hash[:16]}... not found in Sophos database"
                    )
                    return {"threat_level": "UNKNOWN"}

                elif response.status_code == 401:
                    logger.error("Sophos API authentication failed - check API key")
                    return None

                else:
                    logger.warning(
                        f"Sophos API error: {response.status_code} - {response.text}"
                    )
                    return None

        except Exception as e:
            logger.error(f"Sophos API request error: {str(e)}")
            return None

    async def _analyze_file_hash_basic(
        self, file_hash: str, filename: str, position: int
    ) -> List[RiskFactor]:
        """
        Basic file hash analysis without external API (fallback)
        """
        risk_factors = []

        # Simple hash validation
        if len(file_hash) not in [32, 40, 64]:  # MD5, SHA1, SHA256
            risk_factors.append(
                RiskFactor(
                    category="ATTACHMENT",
                    risk="MEDIUM",
                    score=30,
                    description="Invalid file hash format",
                    details=f"Position: {position}, File: {filename}, Hash: {file_hash}",
                )
            )
        else:
            # Hash looks valid but we can't verify it
            risk_factors.append(
                RiskFactor(
                    category="ATTACHMENT",
                    risk="LOW",
                    score=15,
                    description="File hash present but not verified against threat database",
                    details=f"Position: {position}, File: {filename}",
                )
            )

        return risk_factors

    def _static_filename_analysis(self, filename: str) -> List[str]:
        """
        Perform static analysis of filename for suspicious patterns
        """
        risks = []
        filename_lower = filename.lower()

        # Check for dangerous extensions
        for ext in self.dangerous_extensions:
            if filename_lower.endswith(ext):
                risks.append(f"Dangerous file extension: {ext}")
                break

        # Check for double extensions
        if self._has_double_extension(filename):
            risks.append("Double file extension detected (possible disguise)")

        # Check for suspicious patterns
        suspicious_patterns = [
            r"invoice.*\.(exe|scr|bat)$",
            r"receipt.*\.(exe|scr|bat)$",
            r"document.*\.(exe|scr|bat)$",
            r"photo.*\.(exe|scr|bat)$",
            r"update.*\.(exe|scr|bat)$",
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, filename_lower):
                risks.append("Suspicious filename pattern detected")
                break

        # Check for social engineering keywords
        social_eng_keywords = [
            "urgent",
            "invoice",
            "receipt",
            "payment",
            "refund",
            "tax",
            "document",
            "scan",
            "photo",
            "update",
            "patch",
            "install",
        ]

        for keyword in social_eng_keywords:
            if keyword in filename_lower:
                risks.append(f"Social engineering keyword in filename: {keyword}")
                break

        return risks

    def _has_double_extension(self, filename: str) -> bool:
        """
        Check for double file extensions (e.g., document.pdf.exe)
        """
        parts = filename.lower().split(".")
        if len(parts) >= 3:
            common_exts = ["pdf", "doc", "jpg", "png", "txt", "zip", "rar"]
            dangerous_exts = ["exe", "scr", "bat", "cmd", "com"]
            if parts[-2] in common_exts and parts[-1] in dangerous_exts:
                return True
        return False

    def _validate_mime_type(
        self, attachment: AttachmentData, position: int
    ) -> List[RiskFactor]:
        """
        Validate MIME type against filename extension
        """
        risk_factors = []
        filename = attachment.filename.lower()
        mime_type = attachment.mimeType.lower()

        # Expected MIME type mappings
        expected_mime_mapping = {
            ".pdf": "application/pdf",
            ".doc": "application/msword",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".exe": "application/x-msdownload",
            ".zip": "application/zip",
            ".jpg": "image/jpeg",
            ".png": "image/png",
        }

        # Check for MIME type spoofing
        for ext, expected_mime in expected_mime_mapping.items():
            if filename.endswith(ext) and mime_type != expected_mime:
                risk_factors.append(
                    RiskFactor(
                        category="ATTACHMENT",
                        risk="HIGH",
                        score=75,
                        description=f"MIME type mismatch: {mime_type} for {ext} file",
                        details=f"Position: {position}, File: {attachment.filename}",
                    )
                )
                break

        # Check for dangerous MIME types
        dangerous_mime_types = [
            "application/x-msdownload",
            "application/x-executable",
            "application/x-dosexec",
            "text/x-shellscript",
            "application/x-sh",
        ]

        if mime_type in dangerous_mime_types:
            risk_factors.append(
                RiskFactor(
                    category="ATTACHMENT",
                    risk="HIGH",
                    score=85,
                    description=f"Dangerous MIME type detected: {mime_type}",
                    details=f"Position: {position}, File: {attachment.filename}",
                )
            )

        return risk_factors

    def _analyze_file_size(
        self, attachment: AttachmentData, position: int
    ) -> List[RiskFactor]:
        """
        Analyze file size for anomalies
        """
        risk_factors = []
        size = attachment.size
        filename = attachment.filename.lower()

        # Check for unusually large files (over 50MB)
        if size > 50 * 1024 * 1024:
            risk_factors.append(
                RiskFactor(
                    category="ATTACHMENT",
                    risk="MEDIUM",
                    score=40,
                    description=f"Unusually large attachment: {size / (1024*1024):.1f}MB",
                    details=f"Position: {position}, File: {attachment.filename}",
                )
            )

        # Check for suspiciously small executable files
        if any(filename.endswith(ext) for ext in [".exe", ".scr", ".bat"]):
            if size < 1024:  # Less than 1KB
                risk_factors.append(
                    RiskFactor(
                        category="ATTACHMENT",
                        risk="HIGH",
                        score=75,
                        description="Suspiciously small executable file",
                        details=f"Position: {position}, File: {attachment.filename}, Size: {size} bytes",
                    )
                )

        # Check for zero-byte files
        if size == 0:
            risk_factors.append(
                RiskFactor(
                    category="ATTACHMENT",
                    risk="MEDIUM",
                    score=50,
                    description="Zero-byte file attachment",
                    details=f"Position: {position}, File: {attachment.filename}",
                )
            )

        return risk_factors

    def _determine_risk_level(self, risk_description: str) -> str:
        """
        Determine risk level based on description
        """
        high_risk_patterns = [
            "dangerous",
            "malicious",
            "double extension",
            "mime type mismatch",
            "executable",
            "suspicious small",
            "sophos detected",
        ]

        medium_risk_patterns = [
            "suspicious",
            "social engineering",
            "large",
            "zero-byte",
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

        if "malicious" in risk_desc_lower or "dangerous" in risk_desc_lower:
            return min(95, base_score + 20)
        elif "double extension" in risk_desc_lower:
            return min(90, base_score + 15)
        elif "mime type mismatch" in risk_desc_lower:
            return min(85, base_score + 10)

        return base_score
