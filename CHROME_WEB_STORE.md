# Chrome Web Store Prep

Use this checklist and copy when preparing the PhishCheck URL Scanner listing.

Published listing:

```text
https://chromewebstore.google.com/detail/phishcheck-url-scanner/ekmkfgemojeljggbamlglpgikjcenhcg
```

## Package

Zip the contents of `chrome-extension/`, not the parent project folder. The zip should contain `manifest.json`, `popup.html`, `popup.css`, `popup.js`, and the `icons/` folder at the top level.

## Store Listing Draft

Name:

```text
PhishCheck URL Scanner
```

Summary:

```text
Scans the current website URL and shows a rule-based phishing risk score.
```

Description:

```text
PhishCheck URL Scanner checks the website URL in your active Chrome tab and shows a phishing risk score from 0 to 100.

The result includes a Safe, Suspicious, or Dangerous label plus short reasons from a rule-based backend. Current checks include suspicious URL wording, insecure HTTP links, shortened URLs, IP-address links, unusual subdomains, and other common phishing indicators.

This extension is intended for quick triage and learning. It does not guarantee that a website is safe.
```

Category:

```text
Productivity
```

Language:

```text
English
```

## Privacy Tab

Single purpose:

```text
PhishCheck scans the current tab URL when the user opens the extension popup and displays a rule-based phishing risk score with reasons.
```

Permission justification:

```text
activeTab: Required to read the current tab URL only after the user clicks the extension icon.
```

Host permission justification:

```text
https://phishcheck-qnp6.onrender.com/*: Required to send the current URL to the PhishCheck backend API and receive the risk score.
```

Remote code:

```text
No. The extension does not load or execute remote code. It only sends a URL to the backend API and displays the JSON response.
```

Data usage disclosure:

```text
The extension processes website URLs. URLs are sent to the PhishCheck backend only when the user opens the popup or clicks Refresh. The service uses the URL to return a phishing risk score and reasons. The MVP does not include user accounts, advertising, or scan-history storage.
```

Privacy policy URL:

```text
https://phishcheck-qnp6.onrender.com/privacy
```

## Test Instructions

```text
1. Install the extension.
2. Open a normal website tab, such as https://github.com.
3. Click the PhishCheck extension icon.
4. Confirm the popup displays the current URL, a 0-100 risk score, a Safe/Suspicious/Dangerous label, and reasons.
5. Click Refresh to run the scan again.
```
