from pydantic import BaseModel, Field
from typing import List, Dict, Any

class Service(BaseModel):
    port: int
    state: str
    service: str

class Asset(BaseModel):
    ip: str
    services: List[Service]

class Threat(BaseModel):
    id: str
    stride_category: str
    description: str
    evidence: str
    likelihood: str
    impact: str
    mitigation: str

class ThreatModelResult(BaseModel):
    job_id: str
    threats: List[Threat]
