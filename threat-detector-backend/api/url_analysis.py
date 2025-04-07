from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from models.url_analyzer import URLAnalyzer

router = APIRouter()
url_analyzer = URLAnalyzer()  # Initialize the analyzer

class URLCheckRequest(BaseModel):
    url: str

@router.post("/check")
async def check_url(request: URLCheckRequest):
    """
    Check if a URL is malicious.
    Uses a placeholder implementation for now.
    """
    try:
        # Analyze the URL using our placeholder model
        result = url_analyzer.analyze(request.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 