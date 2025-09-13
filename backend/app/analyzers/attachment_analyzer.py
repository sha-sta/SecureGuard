import re
import hashlib
from typing import List, Dict, Any, Optional
import logging
import httpx
import base64

# Optional import for magic library
try:
    import magic

    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
    magic = None

from ..models import AttachmentData, RiskFactor, AttachmentAnalysisResult
from ..config import settings

logger = logging.getLogger(__name__)


class AttachmentAnalyzer:
    """
    Analyzes email attachments for security threats including:
    - File hash reputation checks
    - Static analysis for macros, JavaScript, suspicious extensions
    - File type validation
    - Malware signature detection
    """

    def __init__(self):
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

        self.suspicious_extensions = {
            ".zip",
            ".rar",
            ".7z",
            ".tar",
            ".gz",
            ".iso",
            ".img",
            ".dmg",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".pdf",
            ".rtf",
            ".html",
            ".htm",
        }

        self.double_extension_patterns = [
            r"\.pdf\.exe$",
            r"\.doc\.exe$",
            r"\.jpg\.exe$",
            r"\.png\.exe$",
            r"\.txt\.exe$",
            r"\.zip\.exe$",
            r"\.rar\.exe$",
        ]

        self.office_mime_types = {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/msword",
            "application/vnd.ms-excel",
            "application/vnd.ms-powerpoint",
        }

        self.pdf_mime_types = {"application/pdf"}

    async def analyze_attachments(
        self, attachments: List[AttachmentData]
    ) -> List[RiskFactor]:
        """
        Analyze all attachments in an email
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
                    f"Attachment analysis error for {attachment.filename}: {str(e)}"
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
        Analyze a single attachment and return detailed results
        """
        result = AttachmentAnalysisResult(filename=filename)

        try:
            # Static filename analysis
            static_risks = self._static_filename_analysis(filename)
            result.risk_factors.extend(static_risks)

            # Check for dangerous characteristics
            if any(ext in filename.lower() for ext in self.dangerous_extensions):
                result.is_malicious = True

            if self._has_double_extension(filename):
                result.is_malicious = True

            # Hash reputation check
            if file_hash:
                hash_reputation = await self._check_hash_reputation(file_hash)
                result.hash_reputation = hash_reputation
                if hash_reputation == "MALICIOUS":
                    result.is_malicious = True
                elif hash_reputation == "SUSPICIOUS":
                    result.is_malicious = True  # Err on side of caution

            # Office document analysis
            if self._is_office_document(filename):
                result.has_macros = True  # Assume potential for macros

            # PDF analysis
            if filename.lower().endswith(".pdf"):
                result.has_javascript = True  # Assume potential for JS

        except Exception as e:
            logger.error(f"Single attachment analysis error: {str(e)}")
            result.risk_factors.append(f"Analysis error: {str(e)}")

        return result

    async def _analyze_single_attachment_data(
        self, attachment: AttachmentData, position: int
    ) -> List[RiskFactor]:
        """
        Analyze a single attachment for threats
        """
        risk_factors = []
        filename = attachment.filename

        # 1. Filename analysis
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

        # 2. MIME type validation
        mime_risks = self._validate_mime_type(attachment)
        risk_factors.extend(mime_risks)

        # 3. File size analysis
        size_risks = self._analyze_file_size(attachment)
        risk_factors.extend(size_risks)

        # 4. Hash reputation check
        if attachment.hash:
            hash_risks = await self._analyze_file_hash(attachment.hash, filename)
            risk_factors.extend(hash_risks)
        else:
            # If no hash is provided, we can't do VirusTotal analysis
            risk_factors.append(
                RiskFactor(
                    category="ATTACHMENT",
                    risk="MEDIUM",
                    score=30,
                    description="No file hash provided for malware scanning",
                    details=f"File: {filename} - Cannot verify against VirusTotal database",
                )
            )

        # 5. Office document specific checks
        if self._is_office_document(filename):
            office_risks = self._analyze_office_document(attachment)
            risk_factors.extend(office_risks)

        # 6. PDF specific checks
        if filename.lower().endswith(".pdf"):
            pdf_risks = self._analyze_pdf_document(attachment)
            risk_factors.extend(pdf_risks)

        # 7. Archive analysis
        if self._is_archive_file(filename):
            archive_risks = self._analyze_archive_file(attachment)
            risk_factors.extend(archive_risks)

        return risk_factors

    def _static_filename_analysis(self, filename: str) -> List[str]:
        """
        Perform static analysis of filename
        """
        risks = []
        filename_lower = filename.lower()

        # 1. Check for dangerous extensions
        for ext in self.dangerous_extensions:
            if filename_lower.endswith(ext):
                risks.append(f"Dangerous file extension: {ext}")
                break

        # 2. Check for double extensions
        if self._has_double_extension(filename):
            risks.append("Double file extension detected (possible disguise)")

        # 3. Check for suspicious patterns
        suspicious_patterns = [
            r"invoice.*\.exe$",
            r"receipt.*\.exe$",
            r"document.*\.exe$",
            r"photo.*\.exe$",
            r"image.*\.exe$",
            r"video.*\.exe$",
            r"update.*\.exe$",
            r"patch.*\.exe$",
            r"install.*\.exe$",
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, filename_lower):
                risks.append("Suspicious filename pattern detected")
                break

        # 4. Check for Unicode/homograph attacks
        if self._contains_suspicious_unicode(filename):
            risks.append("Filename contains suspicious Unicode characters")

        # 5. Check for very long filenames
        if len(filename) > 200:
            risks.append("Unusually long filename detected")

        # 6. Check for hidden file extensions (Windows)
        if filename.count(".") > 2:
            risks.append("Multiple dots in filename (possible extension hiding)")

        # 7. Check for social engineering keywords
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
            "image",
            "video",
            "update",
            "patch",
            "install",
            "setup",
            "crack",
            "keygen",
        ]

        for keyword in social_eng_keywords:
            if keyword in filename_lower:
                risks.append(f"Social engineering keyword in filename: {keyword}")
                break

        return risks

    def _has_double_extension(self, filename: str) -> bool:
        """
        Check for double file extensions
        """
        filename_lower = filename.lower()

        for pattern in self.double_extension_patterns:
            if re.search(pattern, filename_lower):
                return True

        # Generic double extension check
        parts = filename_lower.split(".")
        if len(parts) >= 3:
            # Check if second-to-last part looks like a common extension
            common_exts = ["pdf", "doc", "jpg", "png", "txt", "zip", "rar"]
            if parts[-2] in common_exts and parts[-1] in ["exe", "scr", "bat"]:
                return True

        return False

    def _contains_suspicious_unicode(self, filename: str) -> bool:
        """
        Check for suspicious Unicode characters that might be used for obfuscation
        """
        # Check for right-to-left override characters
        if "\u202e" in filename or "\u202d" in filename:
            return True

        # Check for other suspicious Unicode categories
        suspicious_chars = [
            "\u200b",  # Zero-width space
            "\u200c",  # Zero-width non-joiner
            "\u200d",  # Zero-width joiner
            "\ufeff",  # Zero-width no-break space
        ]

        return any(char in filename for char in suspicious_chars)

    def _validate_mime_type(self, attachment: AttachmentData) -> List[RiskFactor]:
        """
        Validate MIME type against filename extension
        """
        risk_factors = []
        filename = attachment.filename.lower()
        mime_type = attachment.mimeType.lower()

        # Check for MIME type spoofing
        expected_mime_mapping = {
            ".pdf": "application/pdf",
            ".doc": "application/msword",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls": "application/vnd.ms-excel",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".txt": "text/plain",
            ".html": "text/html",
            ".zip": "application/zip",
            ".rar": "application/x-rar-compressed",
        }

        for ext, expected_mime in expected_mime_mapping.items():
            if filename.endswith(ext) and mime_type != expected_mime:
                risk_factors.append(
                    RiskFactor(
                        category="ATTACHMENT",
                        risk="HIGH",
                        score=70,
                        description=f"MIME type mismatch: {mime_type} for {ext} file",
                        details=f"File: {attachment.filename}",
                    )
                )
                break

        # Check for dangerous MIME types
        dangerous_mime_types = [
            "application/x-msdownload",  # .exe files
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
                    details=f"File: {attachment.filename}",
                )
            )

        return risk_factors

    def _analyze_file_size(self, attachment: AttachmentData) -> List[RiskFactor]:
        """
        Analyze file size for anomalies
        """
        risk_factors = []
        size = attachment.size
        filename = attachment.filename.lower()

        # Check for unusually large files
        if size > 50 * 1024 * 1024:  # 50MB
            risk_factors.append(
                RiskFactor(
                    category="ATTACHMENT",
                    risk="MEDIUM",
                    score=40,
                    description=f"Unusually large attachment: {size / (1024*1024):.1f}MB",
                    details=f"File: {attachment.filename}",
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
                        details=f"File: {attachment.filename}, Size: {size} bytes",
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
                    details=f"File: {attachment.filename}",
                )
            )

        return risk_factors

    async def _analyze_file_hash(
        self, file_hash: str, filename: str
    ) -> List[RiskFactor]:
        """
        Analyze file hash for reputation
        """
        risk_factors = []

        try:
            reputation = await self._check_hash_reputation(file_hash)

            if reputation == "MALICIOUS":
                risk_factors.append(
                    RiskFactor(
                        category="ATTACHMENT",
                        risk="HIGH",
                        score=95,
                        description="File hash matches known malware",
                        details=f"File: {filename}, Hash: {file_hash[:16]}...",
                    )
                )
            elif reputation == "SUSPICIOUS":
                risk_factors.append(
                    RiskFactor(
                        category="ATTACHMENT",
                        risk="MEDIUM",
                        score=65,
                        description="File hash flagged as suspicious",
                        details=f"File: {filename}, Hash: {file_hash[:16]}...",
                    )
                )

        except Exception as e:
            logger.error(f"Hash reputation check error: {str(e)}")

        return risk_factors

    async def _check_hash_reputation(self, file_hash: str) -> str:
        """
        Check file hash against reputation databases
        Returns: CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN
        """
        try:
            # VirusTotal hash lookup
            if settings.VIRUSTOTAL_API_KEY:
                vt_result = await self._check_virustotal_hash(file_hash)
                if vt_result != "UNKNOWN":
                    return vt_result

            # Additional hash databases could be added here
            # For now, return unknown if no databases are available
            return "UNKNOWN"

        except Exception as e:
            logger.error(f"Hash reputation check error: {str(e)}")
            return "UNKNOWN"

    async def _check_virustotal_hash(self, file_hash: str) -> str:
        """
        Check file hash against VirusTotal using file analysis
        """
        try:
            api_key = settings.VIRUSTOTAL_API_KEY
            api_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

            headers = {"x-apikey": api_key}

            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(api_url, headers=headers)

                if response.status_code == 200:
                    result = response.json()
                    attributes = result.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected

                    logger.info(
                        f"VirusTotal file scan for hash {file_hash[:16]}...: {malicious} malicious, {suspicious} suspicious out of {total} engines"
                    )

                    if malicious > 0:
                        return "MALICIOUS"
                    elif suspicious > 0:
                        return "SUSPICIOUS"
                    elif total > 0:
                        return "CLEAN"
                    else:
                        return "UNKNOWN"

                elif response.status_code == 404:
                    logger.info(
                        f"File hash {file_hash[:16]}... not found in VirusTotal database"
                    )
                    return "UNKNOWN"  # File not in database
                else:
                    logger.warning(f"VirusTotal API error: {response.status_code}")
                    return "UNKNOWN"

        except Exception as e:
            logger.error(f"VirusTotal hash check error: {str(e)}")

        return "UNKNOWN"

    async def _submit_file_to_virustotal(self, file_data: bytes, filename: str) -> dict:
        """
        Submit file to VirusTotal for analysis (for files not in database)
        Note: This requires the actual file content, which we may not have in email analysis
        """
        try:
            api_key = settings.VIRUSTOTAL_API_KEY
            upload_url = "https://www.virustotal.com/api/v3/files"

            headers = {"x-apikey": api_key}
            files = {"file": (filename, file_data)}

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(upload_url, headers=headers, files=files)

                if response.status_code == 200:
                    result = response.json()
                    logger.info(f"Successfully submitted file {filename} to VirusTotal")
                    return result
                else:
                    logger.warning(
                        f"VirusTotal file upload error: {response.status_code}"
                    )
                    return {}

        except Exception as e:
            logger.error(f"VirusTotal file upload error: {str(e)}")
            return {}

    def _is_office_document(self, filename: str) -> bool:
        """
        Check if file is an Office document
        """
        office_extensions = [".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf"]
        return any(filename.lower().endswith(ext) for ext in office_extensions)

    def _analyze_office_document(self, attachment: AttachmentData) -> List[RiskFactor]:
        """
        Analyze Office documents for potential threats
        """
        risk_factors = []

        # Office documents can contain macros
        risk_factors.append(
            RiskFactor(
                category="ATTACHMENT",
                risk="MEDIUM",
                score=45,
                description="Office document may contain macros",
                details=f"File: {attachment.filename}",
            )
        )

        # Check for suspicious Office document names
        suspicious_names = [
            "invoice",
            "receipt",
            "payment",
            "order",
            "statement",
            "document",
            "scan",
            "fax",
            "report",
        ]

        filename_lower = attachment.filename.lower()
        for name in suspicious_names:
            if name in filename_lower:
                risk_factors.append(
                    RiskFactor(
                        category="ATTACHMENT",
                        risk="MEDIUM",
                        score=50,
                        description=f"Office document with suspicious name pattern: {name}",
                        details=f"File: {attachment.filename}",
                    )
                )
                break

        return risk_factors

    def _analyze_pdf_document(self, attachment: AttachmentData) -> List[RiskFactor]:
        """
        Analyze PDF documents for potential threats
        """
        risk_factors = []

        # PDFs can contain JavaScript
        risk_factors.append(
            RiskFactor(
                category="ATTACHMENT",
                risk="MEDIUM",
                score=40,
                description="PDF document may contain JavaScript",
                details=f"File: {attachment.filename}",
            )
        )

        # Check for suspicious PDF names
        suspicious_patterns = [
            "invoice",
            "receipt",
            "statement",
            "report",
            "scan",
            "document",
            "form",
            "application",
        ]

        filename_lower = attachment.filename.lower()
        for pattern in suspicious_patterns:
            if pattern in filename_lower:
                risk_factors.append(
                    RiskFactor(
                        category="ATTACHMENT",
                        risk="MEDIUM",
                        score=45,
                        description=f"PDF with suspicious name pattern: {pattern}",
                        details=f"File: {attachment.filename}",
                    )
                )
                break

        return risk_factors

    def _is_archive_file(self, filename: str) -> bool:
        """
        Check if file is an archive
        """
        archive_extensions = [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso"]
        return any(filename.lower().endswith(ext) for ext in archive_extensions)

    def _analyze_archive_file(self, attachment: AttachmentData) -> List[RiskFactor]:
        """
        Analyze archive files for potential threats
        """
        risk_factors = []

        # Archives can hide malicious content
        risk_factors.append(
            RiskFactor(
                category="ATTACHMENT",
                risk="MEDIUM",
                score=35,
                description="Archive file may contain hidden malicious content",
                details=f"File: {attachment.filename}",
            )
        )

        # Password-protected archives are more suspicious
        if (
            "password" in attachment.filename.lower()
            or "protected" in attachment.filename.lower()
        ):
            risk_factors.append(
                RiskFactor(
                    category="ATTACHMENT",
                    risk="HIGH",
                    score=65,
                    description="Password-protected archive detected",
                    details=f"File: {attachment.filename}",
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
            "hash matches",
        ]

        medium_risk_patterns = [
            "suspicious",
            "macro",
            "javascript",
            "archive",
            "large",
            "unicode",
            "social engineering",
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
