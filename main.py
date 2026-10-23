import os
import glob
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from core.models import AnalyzeRequest, AgentReviewResponse, TestRunRequest, TestRunResponse
from agents.orchestrator import MasterOrchestrator
from core.sandbox import CodeSandbox

app = FastAPI(
    title="CodeSentinel AI: Multi-Agent Code Review & Automated Refactoring",
    description="IBM SkillsBuild & Hacktiv8 Final Project - IT: AI Agent for Programming",
    version="1.0.0"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def root():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/health")
async def health_check():
    return {"status": "online", "system": "CodeSentinel Multi-Agent Platform"}


@app.get("/api/samples")
async def get_samples():
    samples = {}
    if os.path.exists(SAMPLES_DIR):
        for path in glob.glob(os.path.join(SAMPLES_DIR, "*.py")):
            filename = os.path.basename(path)
            with open(path, "r", encoding="utf-8") as f:
                samples[filename] = f.read()
    return samples


@app.post("/api/analyze", response_model=AgentReviewResponse)
async def analyze_code(request: AnalyzeRequest):
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="Code content cannot be empty.")

    try:
        orchestrator = MasterOrchestrator(
            provider=request.provider,
            api_key=request.api_key
        )
        response = await orchestrator.execute_pipeline(
            code=request.code,
            filename=request.filename
        )
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline execution error: {str(e)}")


@app.post("/api/run-tests", response_model=TestRunResponse)
async def run_tests_sandbox(request: TestRunRequest):
    if not request.code.strip() or not request.test_code.strip():
        raise HTTPException(status_code=400, detail="Both source code and test code are required.")

    result = CodeSandbox.run_tests(code=request.code, test_code=request.test_code)
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
