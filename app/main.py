from fastapi import FastAPI, UploadFile, Form
from app.orchestrator import run_threat_enumerator
import asyncio, uuid

app = FastAPI(title="Agentic Threat Modeller")

@app.post("/analyze/")
async def analyze_scan(nmap_file: UploadFile, job_name: str = Form(...)):
    xml_data = await nmap_file.read()
    job_id = f"job-{uuid.uuid4()}"
    threats = await run_threat_enumerator(job_id, xml_data.decode())
    return {"job_id": job_id, "threats": threats}
