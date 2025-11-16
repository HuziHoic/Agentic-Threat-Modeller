import json
import asyncio
import httpx
from pymongo import MongoClient
from app.parsers.nmap_parser import parse_nmap_xml
from app.config import settings
import google.generativeai as genai

genai.configure(api_key=settings.GEMINI_API_KEY)

client = MongoClient(settings.MONGO_URI)
db = client[settings.DB_NAME]


async def call_llm(prompt: str) -> str:
    """
    Calls Gemini and returns raw text output (string).
    """
    model = genai.GenerativeModel(
        "gemini-flash-latest",
        generation_config={
            "response_mime_type": "application/json",
            "temperature": 0.3,
        },
    )

    response = model.generate_content(prompt)

    # Gemini returns a text property containing the JSON string
    return response.text


def parse_ai_output(raw_text: str):
    """
    Attempts to parse Gemini JSON output.
    Supports:
    - a raw JSON list:   [ {...}, {...} ]
    - a wrapped object:  { "threats": [...] }
    """

    try:
        data = json.loads(raw_text)

        # Case 1: Expected wrapped structure
        if isinstance(data, dict) and "threats" in data:
            return data["threats"]

        # Case 2: Gemini often returns a raw list
        if isinstance(data, list):
            return data

        raise ValueError("Unexpected JSON structure")

    except Exception as e:
        return {
            "error": f"Failed to parse LLM output: {str(e)}",
            "raw": raw_text,
        }


async def run_threat_enumerator(job_id: str, nmap_xml: str):
    assets = parse_nmap_xml(nmap_xml)

    prompt = f"""
You are an automated threat modeling agent.

Input assets (from Nmap scan):
{json.dumps(assets, indent=2)}

Task:
Enumerate threats using STRIDE categories (Spoofing, Tampering, Repudiation, 
Information Disclosure, Denial of Service, Elevation of Privilege).

For each threat output these fields:
- id
- stride_category
- description
- evidence
- likelihood (low | medium | high)
- impact
- mitigation

Return ONLY valid JSON.
Return an array of threats OR an object containing `threats`.
"""

    llm_raw_output = await call_llm(prompt)
    threats = parse_ai_output(llm_raw_output)

    db.results.insert_one({"job_id": job_id, "threats": threats})

    return threats
