from fastapi import APIRouter, UploadFile, File, HTTPException
import os
import tempfile
from models.file_analyzer import FileAnalyzer

router = APIRouter()
file_analyzer = FileAnalyzer()  # Initialize the analyzer

@router.post("/check")
async def check_file(file: UploadFile = File(...)):
    """
    Check if a file is malicious.
    Uses a placeholder implementation for now.
    """
    try:
        # Save the file temporarily
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        contents = await file.read()
        temp_file.write(contents)
        temp_file.close()
        
        # Analyze the file using our placeholder model
        result = file_analyzer.analyze(temp_file.name)
        
        # Add filename to the result
        result["filename"] = file.filename
        
        # Clean up the temporary file
        os.unlink(temp_file.name)
        
        return result
    except Exception as e:
        # Make sure temp file is cleaned up in case of error
        if 'temp_file' in locals() and os.path.exists(temp_file.name):
            os.unlink(temp_file.name)
        raise HTTPException(status_code=500, detail=str(e)) 