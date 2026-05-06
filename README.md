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

## Chrome Extension

The extension lives in `chrome-extension/` and checks the current browser tab against the local Flask API.

1. Start the Flask backend first:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   python app.py
   ```

2. Open Chrome and go to:

   ```text
   chrome://extensions
   ```

3. Turn on **Developer mode** in the top-right corner.

4. Click **Load unpacked**.

5. Select this folder:

   ```text
   C:\phishcheck\chrome-extension
   ```

6. Open any normal website, click the PhishCheck extension icon, and the popup will show:

   - A risk score from 0-100
   - A Safe, Suspicious, or Dangerous label
   - The rule-based reasons returned by the backend

## Notes

This MVP uses rule-based detection only. It is meant for quick triage and demos, not as a replacement for production email security tools.
