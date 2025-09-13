from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
import logging
from contextlib import asynccontextmanager

from pydantic import BaseModel

from .config import settings
from .models import EmailData, AnalysisResponse, RiskScore, RiskFactor
from .analyzers.header_analyzer import HeaderAnalyzer
from .analyzers.link_analyzer import LinkAnalyzer
from .analyzers.attachment_analyzer import AttachmentAnalyzer
from .analyzers.content_analyzer import ContentAnalyzer
from .analyzers.risk_scorer import RiskScorer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting SecureGuard API...")
    yield
    # Shutdown
    logger.info("Shutting down SecureGuard API...")


# Create FastAPI app
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Initialize analyzers
header_analyzer = HeaderAnalyzer()
link_analyzer = LinkAnalyzer()
attachment_analyzer = AttachmentAnalyzer()
content_analyzer = ContentAnalyzer()
risk_scorer = RiskScorer()


@app.get("/")
async def root():
    return {
        "message": "SecureGuard Email Scam Detection API",
        "version": settings.VERSION,
        "status": "active",
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": time.time()}


@app.post("/analyze-email", response_model=AnalysisResponse)
async def analyze_email(email_data: EmailData):
    print(email_data.body.encode("utf-8"))
    """
    Analyze an email for potential scams and security threats.
    """
    start_time = time.time()

    try:
        logger.info(f"Analyzing email from: {email_data.from_address}")

        # Validate email size
        email_size = len(email_data.body.encode("utf-8"))
        if email_size > settings.MAX_EMAIL_SIZE:
            raise HTTPException(
                status_code=413, detail="Email size exceeds maximum allowed limit"
            )

        # Initialize results list
        risk_factors = []

        # 1. Header Analysis
        try:
            header_result = await header_analyzer.analyze(email_data)
            if header_result:
                risk_factors.extend(header_result)
        except Exception as e:
            logger.error(f"Header analysis failed: {str(e)}")

        # 2. Link Analysis
        try:
            if email_data.links:
                link_results = await link_analyzer.analyze_links(email_data.links)
                risk_factors.extend(link_results)
        except Exception as e:
            logger.error(f"Link analysis failed: {str(e)}")

        # 3. Attachment Analysis
        try:
            if email_data.attachments:
                attachment_results = await attachment_analyzer.analyze_attachments(
                    email_data.attachments
                )
                risk_factors.extend(attachment_results)
        except Exception as e:
            logger.error(f"Attachment analysis failed: {str(e)}")

        # 4. Content Analysis
        try:
            content_results = await content_analyzer.analyze_content(
                email_data.subject, email_data.body
            )
            if content_results:
                risk_factors.extend(content_results)
        except Exception as e:
            logger.error(f"Content analysis failed: {str(e)}")

        # 5. Calculate overall risk score
        risk_score = risk_scorer.calculate_risk_score(risk_factors)

        processing_time = time.time() - start_time
        logger.info(
            f"Analysis completed in {processing_time:.2f}s - Risk: {risk_score.overall}"
        )

        return AnalysisResponse(
            success=True, riskScore=risk_score, processingTime=processing_time
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email analysis failed: {str(e)}")
        processing_time = time.time() - start_time

        return AnalysisResponse(
            success=False, error=str(e), processingTime=processing_time
        )


@app.get("/stats")
async def get_stats():
    """
    Get API usage statistics.
    """
    # This would typically come from a database
    return {
        "emails_analyzed": 0,
        "threats_detected": 0,
        "uptime": time.time(),
        "version": settings.VERSION,
    }


@app.post("/analyze-url")
async def analyze_url(url: str):
    """
    Analyze a single URL for threats.
    """
    try:
        result = await link_analyzer.analyze_single_url(url)
        return {"success": True, "result": result}
    except Exception as e:
        logger.error(f"URL analysis failed: {str(e)}")
        return {"success": False, "error": str(e)}


@app.post("/analyze-attachment")
async def analyze_attachment(filename: str, file_hash: str = None):
    """
    Analyze a single attachment for threats.
    """
    try:
        result = await attachment_analyzer.analyze_single_attachment(
            filename, file_hash
        )
        return {"success": True, "result": result}
    except Exception as e:
        logger.error(f"Attachment analysis failed: {str(e)}")
        return {"success": False, "error": str(e)}


@app.post("/analyze-email-detailed", response_model=AnalysisResponse)
async def analyze_email_detailed(email_data: EmailData):
    """
    Analyze an email with detailed breakdown for Chrome extension
    """
    # Use the same analysis as the regular endpoint
    result = await analyze_email(email_data)

    # The Chrome extension will handle the detailed breakdown
    # by processing the risk factors
    return result


class PagePayload(BaseModel):
    url: str
    timestamp: str
    html: str


@app.post("/webscrapping")
async def webscrapping_placeholder(payload: PagePayload):
    print("URL:", payload.url)
    print("Timestamp:", payload.timestamp)
    print("HTML length:", len(payload.html))
    print(payload.html)
    return {"status": "success"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG
    )
