from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
from detector import unified_phishing_detector
from dfa_keywords import SUSPICIOUS_KEYWORDS

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


@app.post("/scan")
async def scan_url(request: URLRequest):
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
        matches, indicators, risk, dfa_visualizations = unified_phishing_detector(request.url)
        
        matched_keywords = []
        text_lower = request.url.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in text_lower:
                matched_keywords.append(keyword)
        
        risk_level_map = {
            "SAFE": "safe",
            "SUSPICIOUS": "medium",
            "HIGH RISK / PHISHING": "high"
        }
        
        return {
            "url": request.url,
            "is_suspicious": matches > 0,
            "risk_level": risk_level_map.get(risk, "medium"),
            "suspicious_flags": {
                "has_suspicious_keywords": indicators.get("Suspicious Keywords", False),
                "has_symbol_abuse": indicators.get("Symbol Abuse", False),
                "has_ip_address": indicators.get("IP-Based URL", False),
                "has_suspicious_tld": indicators.get("Suspicious TLD", False),
                "has_encoded_chars": indicators.get("Encoded Characters", False)
            },
            "matched_keywords": matched_keywords if matched_keywords else None,
            "dfa_analysis": dfa_visualizations
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error scanning URL: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
