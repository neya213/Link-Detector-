import pprint
from typing import TypedDict
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
from .detector import DfaPayload, SuspiciousFlags, unified_phishing_detector
from .dfa_keywords import SUSPICIOUS_KEYWORDS_WEIGHTS
from urllib.parse import urlparse

import requests as client


app = FastAPI(
    title="Phishing URL Detector API",
    description="DFA-based phishing detection backend service with state visualization",
    version="2.0.0"
)

# Configure CORS for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLRequest(BaseModel):
    url: str
    
    @validator('url')
    def validate_url(cls, v):
        if not v or not v.strip():
            raise ValueError('URL cannot be empty')
        return v.strip()


@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Phishing URL Detector API with DFA State Visualization",
        "version": "2.0.0",
        "endpoints": {
            "POST /scan": "Scan a URL for phishing indicators with DFA state transitions",
            "GET /health": "Health check endpoint",
            "GET /docs": "Interactive API documentation"
        },
        "features": [
            "5 DFA-based detection methods",
            "Complete state transition tracking",
            "Pattern matching visualization",
            "Formal automata analysis"
        ]
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "phishing-detector"}



# the main focus of this project is the detection, using a library is okay.
def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([
            result.scheme in ("http", "https"),
            result.netloc != "",
        ])
    except Exception:
        return False


class HTTPRedirect(TypedDict):
    has_redirects: bool
    previous_url: str
    final_url: str

class ScanResult(TypedDict):
    url: str
    risk_level: str
    risk_score: float
    suspicious_flags: SuspiciousFlags
    redirects: HTTPRedirect | None
    payload: DfaPayload


@app.post("/scan")
async def scan_url(request: URLRequest) -> ScanResult:
    """
    Scan a URL for phishing indicators with complete DFA state visualization.
    
    Returns detailed analysis including:
    - Individual indicator results
    - Total number of matches
    - Risk level assessment
    - Boolean phishing flag
    - DFA state transitions for each detector (for automata theory demonstration)
    """
    try:
        if not is_valid_url(request.url):
            raise HTTPException(status_code=500, detail="Error scanning URL: The URL provided is not a valid URL.")

        final_url: str = request.url
        has_redirects = False
        # this follows redirects 
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            response = client.get(request.url, headers=headers, timeout=(2, 4)) # getting the long links from short links
            has_redirects = True
            final_url = response.url
        except Exception as e:
            print(f"Error: {e}")

        risk_score, indicators, verdict, payload = unified_phishing_detector(final_url)
        
        matched_keywords: list[str] = []
        text_lower = request.url.lower()
        for keyword in SUSPICIOUS_KEYWORDS_WEIGHTS:
            if keyword in text_lower:
                matched_keywords.append(keyword)
        
        risk_level_map = {
            "SAFE": "safe",
            "SUSPICIOUS": "medium",
            "HIGH RISK / PHISHING": "high"
        }
        redirect = HTTPRedirect(
            has_redirects=has_redirects,
            previous_url=request.url,
            final_url=final_url
        )

        pprint.pprint(payload)
        
        return {
            "url": request.url,
            "risk_score": risk_score,
            "risk_level": risk_level_map.get(verdict, "medium"),
            "suspicious_flags": indicators,
            "redirects": redirect,
            "payload": payload,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error scanning URL: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
