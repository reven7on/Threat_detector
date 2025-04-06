from fastapi import APIRouter, UploadFile, File, HTTPException
import os
import tempfile
import logging
from models.file_analyzer import FileAnalyzer

# Настройка логирования
logger = logging.getLogger("threat-detector")

router = APIRouter()
file_analyzer = FileAnalyzer()  # Initialize the analyzer

@router.post("/check")
async def check_file(file: UploadFile = File(...)):
    """
    Check if a file is malicious.
    Uses a placeholder implementation for now.
    """
    logger.info(f"Received file for analysis: {file.filename}, size: {file.size} bytes")
    
    try:
        # Save the file temporarily
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        logger.info(f"Created temporary file: {temp_file.name}")
        
        # Read file in chunks to avoid memory issues with large files
        CHUNK_SIZE = 1024 * 1024  # 1MB chunks
        contents = bytearray()
        
        while True:
            chunk = await file.read(CHUNK_SIZE)
            if not chunk:
                break
            contents.extend(chunk)
        
        logger.info(f"Read {len(contents)} bytes from uploaded file")
        temp_file.write(contents)
        temp_file.close()
        
        # Analyze the file using our placeholder model
        logger.info(f"Starting file analysis for {file.filename}")
        result = file_analyzer.analyze(temp_file.name)
        logger.info(f"Analysis completed: {'malicious' if result.get('is_malware') else 'safe'}")
        
        # Add filename to the result
        result["filename"] = file.filename
        
        # Clean up the temporary file
        logger.info(f"Cleaning up temporary file: {temp_file.name}")
        os.unlink(temp_file.name)
        
        return result
    except Exception as e:
        logger.error(f"Error during file analysis: {str(e)}", exc_info=True)
        # Make sure temp file is cleaned up in case of error
        if 'temp_file' in locals() and os.path.exists(temp_file.name):
            try:
                os.unlink(temp_file.name)
                logger.info(f"Cleaned up temporary file after error: {temp_file.name}")
            except Exception as cleanup_error:
                logger.error(f"Failed to clean up temporary file: {str(cleanup_error)}")
        
        # Return a more detailed error response
        raise HTTPException(
            status_code=500, 
            detail={
                "message": "Error analyzing file",
                "error": str(e),
                "filename": file.filename if file else "unknown"
            }
        ) 