from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import os

app = FastAPI()

# Add CORS middleware to allow requests from Flutter app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (for development only)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Ensure the uploads directory exists
os.makedirs("uploads", exist_ok=True)

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload a file to the server.
    """
    try:
        # Save the file to the uploads directory
        file_location = f"uploads/{file.filename}"
        with open(file_location, "wb") as buffer:
            buffer.write(await file.read())

        return JSONResponse(
            content={"message": "File uploaded successfully", "filename": file.filename},
            status_code=200,
        )
    except Exception as e:
        return JSONResponse(
            content={"message": f"File upload failed: {str(e)}"},
            status_code=500,
        )

@app.get("/download")
async def download_file(file: str):
    """
    Download a file from the server.
    """
    try:
        file_location = f"uploads/{file}"
        if not os.path.exists(file_location):
            return JSONResponse(
                content={"message": "File not found"},
                status_code=404,
            )

        return FileResponse(file_location, filename=file)
    except Exception as e:
        return JSONResponse(
            content={"message": f"File download failed: {str(e)}"},
            status_code=500,
        )

@app.get("/execute")
def execute_command(command: str):
    """
    Execute a shell command and return the result.
    """
    try:
        # Run the command using subprocess
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        # Check if the command executed successfully
        if result.returncode == 0:
            return {"command": command, "result": result.stdout}
        else:
            return {"command": command, "error": result.stderr}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Command execution failed: {str(e)}",
        )

# Run the FastAPI app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)