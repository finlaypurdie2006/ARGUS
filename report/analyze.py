"""Send raw recon output to Claude, get back structured findings as JSON."""
import json
import os
from anthropic import Anthropic

SYSTEM_PROMPT = """You are a security analyst. You will be given raw output from \
reconnaissance tools (nmap, whatweb, nikto, gobuster, subfinder) run against an \
authorized target (the operator's own lab system).

Analyze the output and respond with ONLY valid JSON (no markdown fences, no preamble) \
matching this exact schema:

{
  "summary": "2-4 sentence executive summary",
  "risk_level": "Low|Medium|High|Critical",
  "open_ports": [{"port": "string", "service": "string", "version": "string", "note": "string"}],
  "findings": [
    {
      "title": "string",
      "severity": "Info|Low|Medium|High|Critical",
      "description": "string",
      "evidence": "short relevant excerpt from tool output",
      "recommendation": "string"
    }
  ],
  "subdomains": ["list of discovered subdomains, empty if none"],
  "directories": ["list of discovered web paths, empty if none"]
}

Base every finding strictly on the provided tool output. Do not invent results. \
If a tool produced no output or errored, do not fabricate findings for it."""


def analyze(recon_data: dict, model: str = "claude-sonnet-4-6") -> dict:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable not set")

    client = Anthropic(api_key=api_key)

    user_content = "RAW RECON OUTPUT:\n\n" + json.dumps(recon_data, indent=2)[:50000]

    response = client.messages.create(
        model=model,
        max_tokens=4000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    )

    text = "".join(block.text for block in response.content if block.type == "text")
    text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "summary": "Claude's response could not be parsed as JSON. Raw output included below.",
            "risk_level": "Unknown",
            "open_ports": [],
            "findings": [{
                "title": "Report parsing error",
                "severity": "Info",
                "description": text[:2000],
                "evidence": "",
                "recommendation": "Re-run analysis or inspect raw recon data manually.",
            }],
            "subdomains": [],
            "directories": [],
        }
