import json
from app.api.analyze import analyze
from app.models.schemas import AnalyzeRequest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

scenarios = [
    {
        "name": "TEST SCENARIO 1: BASIC SENSITIVE DATA LEAK",
        "input": "2026-03-10 10:00:01 INFO User login\nemail=admin@company.com\npassword=admin123\napi_key=sk-prod-xyz",
    },
    {
        "name": "TEST SCENARIO 2: STACK TRACE + ERROR LEAK",
        "input": "2026-03-10 ERROR NullPointerException at service.java:45\nDEBUG stack trace: line 45 -> service failed",
    },
    {
        "name": "TEST SCENARIO 3: BRUTE FORCE DETECTION",
        "input": "2026-03-10 INFO login failed for user admin\n2026-03-10 INFO login failed for user admin\n2026-03-10 INFO login failed for user admin\n2026-03-10 INFO login failed for user admin\n2026-03-10 INFO login failed for user admin",
    },
    {
        "name": "TEST SCENARIO 4: TOKEN + API KEY EXPOSURE",
        "input": "INFO token=abc123xyz\nINFO api_key=sk-test-987654",
    },
    {
        "name": "TEST SCENARIO 5: CLEAN LOG (CONTROL CASE)",
        "input": "2026-03-10 INFO Server started successfully\n2026-03-10 INFO Health check passed",
    },
    {
        "name": "TEST SCENARIO 6: COMPLEX MIXED CASE (BEST DEMO)",
        "input": "2026-03-10 INFO User login\nemail=user@test.com\npassword=pass123\n2026-03-10 ERROR Exception at controller.java:22\nDEBUG mode enabled\ntoken=xyz-token-123",
    }
]

def run():
    print("========================================")
    for idx, sc in enumerate(scenarios, 1):
        print(f"Running {sc['name']}")
        print("INPUT:")
        print(sc["input"])
        print("-" * 20)
        
        # We need to test it as a log input type
        # Options mask=True, block_high_risk=False seems to align with user action="masked" mostly.
        # Actually user output expected: action="masked" for all except clean case.
        payload = {
            "input_type": "log",
            "content": sc["input"],
            "options": {
                "mask": True,
                "block_high_risk": False,
                "log_analysis": True
            }
        }
        res = client.post("/analyze", json=payload)
        data = res.json()
        print("OUTPUT:")
        print(json.dumps(data, indent=2))
        print("========================================\n")

if __name__ == "__main__":
    run()
