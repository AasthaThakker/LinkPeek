# LinkPeek

<p align="center">
  <img src="./icon.png" width="120" alt="Project Icon">
</p>

A lightweight browser extension that helps you quickly inspect suspicious links before opening them.

Instead of manually checking every URL on multiple websites, LinkPeek gives a quick contextual overview directly inside the browser, useful for security enthusiasts, SOC analysts, researchers, or anyone who deals with lots of links daily.

> This project is still under active development and ongoing improvements are being made for better stealth detection, performance optimization, and overall user experience.

---

## Features

* Suspicious URL detection
* Typosquatting & impersonation checks
* Hover-based risk previews
* Redirect chain tracing
* DNS & domain intelligence lookup
* Fake login page detection
* Contextual risk scoring
* VirusTotal integration support

---

## Tech Stack

* JavaScript
* Chrome Extension APIs
* HTML / CSS
* DNS-over-HTTPS
* RDAP & reputation APIs

---

## Project Structure

```bash
├── background.js      # Handles scans, redirects, DNS & reputation checks
├── content.js         # Runtime page monitoring & hover analysis
├── popup.html         # Extension interface
├── popup.css          # Styling & UI components
├── popup.js           # Main frontend logic
├── utils.js           # Detection & heuristic utilities
├── manifest.json      # Extension configuration
```

---

## Installation

1. Clone this repository

```bash
git clone <your-repo-link>
```

2. Open Chrome and go to:

```bash
chrome://extensions
```

3. Enable **Developer Mode**

4. Click **Load Unpacked**

5. Select the project folder

---

## Why This Project?

Sometimes a link looks normal at first glance but hides small indicators that most users miss.

This extension was built to simplify that process by providing a quick browser-side analysis layer without needing to constantly switch between external tools.

---

## Current Status

The project is functional but still evolving. Planned improvements include:

* Better phishing behavior detection
* Improved tooltip performance
* Smarter contextual analysis
* Cleaner UI/UX
* Additional threat intelligence integrations

---

## Disclaimer
No automated scanner can guarantee complete accuracy. Always verify sensitive links and domains manually when possible.

