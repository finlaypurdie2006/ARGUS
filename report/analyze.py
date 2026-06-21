"""Send raw recon output to Claude, get back structured findings as JSON."""
import json
import os
from anthropic import Anthropic

SYSTEM_PROMPT = """You are a security analyst writing a reconnaissance report in the \
style of a professional penetration-test findings report (executive summary, scope, \
findings with evidence, prioritized remediation). You will be given raw output from \
reconnaissance tools (nmap, whatweb, nikto, gobuster, subfinder) and structured checks \
(TLS certificate inspection under the "ssl" key, HTTP security header presence under the \
"security_headers" key) run against an authorized target (the operator's own lab system).

Treat an expired or soon-expiring TLS certificate, a weak protocol/cipher, or missing \
security headers (Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, \
X-Content-Type-Options, Referrer-Policy, Permissions-Policy) as legitimate findings in \
their own right, with a severity appropriate to the real-world exploitability of the gap.

Analyze the output and respond with ONLY valid JSON (no markdown fences, no preamble) \
matching this exact schema:

{
  "summary": "3-5 sentence executive summary: what was tested, overall risk posture, business impact in plain language",
  "risk_level": "Low|Medium|High|Critical",
  "open_ports": [
    {
      "port": "string",
      "service": "string",
      "version": "string",
      "note": "1 sentence on why this port/service matters from a security standpoint"
    }
  ],
  "findings": [
    {
      "title": "string",
      "severity": "Info|Low|Medium|High|Critical",
      "description": "2-4 sentences: what was found and the practical risk it poses",
      "evidence": "short relevant excerpt from tool output",
      "cve": "CVE ID if the version/banner clearly matches a known CVE, else empty string",
      "attack_vector": "1-2 sentences naming the general exploitation technique/class an attacker could use (e.g. 'unauthenticated RCE via crafted FTP username', 'path traversal to arbitrary file read via CGI handler'). Name the technique/class, not a ready-to-run exploit command, payload, or script.",
      "recommendation": "1-2 sentence immediate fix for this specific finding"
    }
  ],
  "subdomains": ["list of discovered subdomains, empty if none"],
  "directories": ["list of discovered web paths, empty if none"],
  "remediation_plan": [
    {
      "priority": "Immediate|Short-term|Long-term",
      "action": "short imperative action title, e.g. 'Patch OpenSSH to latest stable'",
      "detail": "3-5 sentences of concrete remediation guidance: how to fix it, why it matters, and any relevant hardening standard or best practice to follow"
    }
  ]
}

Guidance for attack_vector: name the class of attack and the realistic path to exploitation \
in general terms (what an attacker would target and why it works), suitable for a CTF/HTB-style \
practice writeup. Do not provide ready-to-run exploit code, specific payloads, or step-by-step \
weaponization commands — that belongs in the operator's own exploitation tooling, not this report.

Guidance for remediation_plan: consolidate root causes across all findings rather than \
repeating each finding 1:1. "Immediate" = fixes for Critical/High findings with a clear \
exploit path. "Short-term" = Medium findings and quick hardening wins. "Long-term" = \
process/architecture improvements (patch management, monitoring, segmentation, etc.) \
that reduce recurrence. Order remediation_plan by priority (Immediate first).

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
                "cve": "",
                "attack_vector": "",
                "recommendation": "Re-run analysis or inspect raw recon data manually.",
            }],
            "subdomains": [],
            "directories": [],
            "remediation_plan": [],
        }
