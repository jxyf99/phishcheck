# PhishCheck

A simple Flask SaaS MVP that analyzes pasted emails or URLs with rule-based phishing checks and returns a 0-100 risk score with reasons.

## What It Checks

- Urgency and pressure words
- Suspicious or insecure links
- Shortened URLs
- Mismatched domains in HTML links
- Requests for passwords, codes, or sensitive account data
- Suspicious attachment file types

## Run Locally

1. Create a virtual environment:

   ```powershell
   python -m venv .venv
   ```

   If PowerShell says `python` is not recognized, install Python 3.11 or newer from [python.org](https://www.python.org/downloads/windows/) and enable **Add python.exe to PATH** during installation. Then close and reopen PowerShell.

2. Activate it:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

3. Install dependencies:

   ```powershell
   pip install -r requirements.txt
   ```

4. Start the app:

   ```powershell
   python app.py
   ```

5. Open your browser to:

   ```text
   http://127.0.0.1:5000
   ```

## Notes

This MVP uses rule-based detection only. It is meant for quick triage and demos, not as a replacement for production email security tools.
