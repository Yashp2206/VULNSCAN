import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3"

def generate_ai(report):

    prompt = f"""
You are a cybersecurity expert.

Analyze the following vulnerability scan.

Provide:

1. Executive Summary
2. Risk Level (Low/Medium/High/Critical)
3. Security Score out of 100
4. Vulnerabilities Found
5. Recommendations
6. Conclusion

Scan Report:

{report}
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        }
    )

    return response.json()["response"]