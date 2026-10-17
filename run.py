"""Entry point — run with: python run.py"""
import os
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("CLOUDGUARD_PORT", 8000))
    uvicorn.run("backend.main:app", host="127.0.0.1", port=port, reload=False)
