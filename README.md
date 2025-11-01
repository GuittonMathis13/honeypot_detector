# Honeypot Detector Pro

Honeypot Detector Pro is a proof-of-concept tool for assessing the risk of
ERC-20 tokens. It combines a Python back-end with a modern React front-end
to provide both command-line and web-based analysis capabilities. The goal
of this project is **not** to guarantee the safety of any token but to
demonstrate an understanding of how honeypot scams operate and how static
analysis can surface the most common red flags.

## Architecture Overview

honeypot_detector/
├── backend/ # Python analysis API
│ ├── analyzer.py # fetches code and applies heuristics
│ ├── rules.py # individual checks for red flags
│ ├── report.py # scoring and summary generation
│ ├── main.py # FastAPI app and CLI entry point
│ └── requirements.txt
├── frontend/ # React front-end
│ ├── src/
│ │ ├── App.tsx # main component
│ │ ├── api.ts # API helper
│ │ ├── index.css # Tailwind directives
│ │ ├── main.tsx # React entry point
│ │ └── components/
│ │ └── ReportCard.tsx
│ ├── package.json
│ ├── postcss.config.cjs
│ ├── tailwind.config.cjs
│ └── vite.config.ts
├── tests/ # automated unit tests (to be expanded)
│ └── test_analyzer.py
├── example_reports/ # sample JSON outputs
└── README.md # project documentation

## Back-end (Python)

The back-end is built with **FastAPI** for the HTTP API and can also be
used as a stand-alone command-line tool. It performs the following steps:

1. **Input validation** – ensures the address looks like a valid Ethereum contract address.
2. **Source retrieval** – uses direct HTTP calls to the Etherscan-family APIs
   to obtain the contract’s verified source code (if available). If the
   source is not verified, this is treated as a red flag.
3. **Static analysis** – runs a series of heuristics defined in `rules.py` to
   detect patterns associated with honeypots and rug pulls (editable fees,
   blacklist/whitelist logic, LP restrictions, paused trading, owner control,
   proxies, etc.).
4. **Scoring and summary** – converts the set of detected flags into a 0–10
   score and a qualitative risk category (SAFE, MEDIUM or HIGH), plus a short summary.

The analyser supports multiple chains. By default it targets **Ethereum**, but
you can specify **BSC** (`bsc`) or **Polygon** (`polygon`) via the `chain` parameter.
It also detects proxy patterns (e.g. `delegatecall`, `eip1967`, `implementation`).

The API exposes a single POST endpoint at `/analyze` which accepts a JSON
body of the form `{ "address": "0x...", "chain": "ethereum|bsc|polygon" }` and returns a report:

```json
{
  "address": "0x123...",
  "score": 7,
  "risk": "HIGH",
  "flags": ["modifiable_fee", "blacklist_whitelist", "owner_not_renounced"],
  "summary": "Contract allows tax or fee parameters to be modified by privileged accounts. Contract contains blacklist/whitelist or transfer restrictions that can block users. Ownership is active and `onlyOwner` functions exist without renunciation."
}
CLI
You can run the same analysis from the command line:

sh
Copier le code
python -m backend.main 0xYourTokenAddress --chain ethereum
# or via the thin wrapper:
./cli.py 0xYourTokenAddress --chain bsc --out report.json
Environment
The application loads API keys from environment variables (or from a local .env):

ETHERSCAN_API_KEY — used for Ethereum and as a fallback

BSCSCAN_API_KEY — optional

POLYGONSCAN_API_KEY — optional

Example .env:

env
Copier le code
ETHERSCAN_API_KEY=YOUR_ETHERSCAN_KEY
BSCSCAN_API_KEY=YOUR_BSCSCAN_KEY
POLYGONSCAN_API_KEY=YOUR_POLYGON_KEY
Usage
Install dependencies:

sh
Copier le code
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
Start the API server (development):

sh
Copier le code
uvicorn backend.main:app --reload
Submit a contract for analysis (replace 0x... with a contract address):

sh
Copier le code
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"address":"0x...","chain":"ethereum"}'
(Optional) Run the CLI:

sh
Copier le code
python -m backend.main 0xYourTokenAddress --chain ethereum
./cli.py 0xYourTokenAddress --chain bsc --out report.json
Front-end (React)
The front-end is a React single-page application (Vite + TypeScript + Tailwind).
Features:

Enter an ERC-20 contract address and trigger the back-end analysis

Select target chain (Ethereum / BSC / Polygon)

See the score and risk category (progress bar + icons)

Review the detected red flags with tooltips

Local history of the last 3 analyses (stored in localStorage)

Download the JSON report

During development, Vite proxies /analyze to the FastAPI server on port 8000.

Run the front-end:

sh
Copier le code
cd frontend
npm install
npm run dev
# open http://localhost:5173
For production, you can either serve the built assets from a static host, or mount the
React build via FastAPI (future work).

Tests
The tests/ directory contains examples for unit tests of the analysis logic.
They rely on stubbing/mocking calls so tests don’t require real API keys.

Disclaimer
This project is provided for educational purposes and should not be considered
financial advice. Always perform your own due diligence before interacting with tokens.



