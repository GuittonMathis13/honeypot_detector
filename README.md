# Honeypot Detector Pro

Honeypot Detector Pro is a proof‑of‑concept tool for assessing the risk of
ERC‑20 tokens. It combines a Python back‑end with a modern React front‑end
to provide both command‑line and web‑based analysis capabilities. The goal
of this project is **not** to guarantee the safety of any token but to
demonstrate an understanding of how honeypot scams operate and how static
analysis can surface the most common red flags.

## Architecture Overview

```
honeypot_detector/
├── backend/           # Python analysis API
│   ├── analyzer.py    # fetches code and applies heuristics
│   ├── rules.py       # individual checks for red flags
│   ├── report.py      # scoring and summary generation
│   ├── main.py        # FastAPI app and CLI entry point
│   └── requirements.txt
├── frontend/          # React front‑end
│   ├── src/
│   │   ├── App.tsx          # composant principal
│   │   ├── api.ts           # fonctions d’appel à l’API
│   │   ├── index.css        # Tailwind directives
│   │   ├── main.tsx         # point d’entrée React
│   │   └── components/
│   │       └── ReportCard.tsx
│   ├── package.json
│   ├── postcss.config.cjs
│   ├── tailwind.config.cjs
│   └── vite.config.ts
├── tests/             # automated unit tests (to be expanded)
│   └── test_analyzer.py
├── example_reports/   # sample JSON outputs
└── README.md          # project documentation
```

### Back‑end (Python)

The back‑end is built with **FastAPI** for the HTTP API and can also be
used as a stand‑alone command‑line tool. It performs the following steps:

1. **Input validation** – ensures the address looks like a valid Ethereum contract address.
2. **Source retrieval** – uses either the `etherscan-python` wrapper or a direct
   HTTP request to Etherscan’s API to obtain the contract’s source code. If
   the source is not verified, this is treated as a red flag【933481489912976†L290-L304】.
3. **Static analysis** – runs a series of simple heuristics defined in
   `rules.py` to detect patterns associated with honeypots and rug pulls,
   such as editable fees, blacklist/whitelist logic, liquidity pool
restrictions or paused trading【933481489912976†L374-L399】.

The analyser supports multiple chains. By default it targets the
**Ethereum** mainnet, but you can specify **Binance Smart Chain** (`bsc`) or
**Polygon** (`polygon`) via the `chain` parameter. It also detects proxy
patterns (use of `delegatecall`), which can allow the logic to be upgraded
after deployment.
4. **Scoring and summary** – converts the set of detected flags into a 0–10
   score and qualitative risk category (safe, medium or high). A short
   description summarises the issues for the user.

The API exposes a single POST endpoint at `/analyze` which accepts a JSON
body of the form `{ "address": "0x..." }` and returns a report:

```json
{
  "address": "0x123...",
  "score": 7,
  "risk": "HIGH",
  "flags": ["modifiable_fee", "blacklist_whitelist", "owner_not_renounced"],
  "summary": "Contract allows tax or fee parameters to be modified by privileged accounts. Contract contains blacklist/whitelist or transfer restrictions that can block users. Ownership is active and `onlyOwner` functions exist without renunciation."
}
```

The same analysis can be performed from the command line via:

```sh
python -m honeypot_detector.backend.main 0xYourTokenAddress
```

You can also specify optional parameters:

```sh
# Analyse a BSC contract and write the report to a file
python -m honeypot_detector.backend.main 0xYourTokenAddress --chain bsc --out report.json
```

The `--chain` option accepts `ethereum`, `bsc` or `polygon`. The `--out`
option writes the JSON report to the given file path.

The application loads the Etherscan API key from the environment
variable `ETHERSCAN_API_KEY`. You can set this in your shell or
store it in a `.env` file in the project root – `python‑dotenv` will
automatically load it at start‑up – so you don’t need to export it every
time.

### Front‑end (React)

The front‑end is a **React** single‑page application built with
**Vite** and **TypeScript**. It provides a minimalist interface where
users can:

1. Saisir une adresse de contrat ERC‑20 et lancer l’analyse via le backend.
2. Sélectionner le réseau cible (Ethereum, BSC ou Polygon) dans une liste déroulante.
3. Visualiser le score et la catégorie de risque avec une barre de progression colorée et des icônes.
4. Consulter la liste des “red flags” détectés et un résumé des risques identifiés (chaque drapeau est accompagné d’une icône et d’un info‑bulle). 
5. Accéder à l’historique local des trois dernières analyses (stocké dans `localStorage`) et l’effacer d’un clic.
6. Télécharger le rapport JSON pour chaque contrat analysé.

Tailwind CSS est utilisé pour un design sobre et réactif, et `react-icons`
apporte des symboles visuels. Pendant le développement, Vite proxy les
requêtes `/analyze` vers le serveur FastAPI (port 8000).

### Tests

The `tests/` directory will contain unit tests for the analysis logic. A
sample test file is provided to illustrate how the `rules` and `report`
modules can be exercised without hitting the Etherscan API.

### Example Reports

`example_reports/` will hold sample JSON outputs for a “safe” token and a
known scam token. These reports can be used to test the front‑end without
connecting to the API.

## Future Improvements

To keep the project deliverable within a short timeframe, many
enhancements have been left as **future work**. Some ideas include:

- Integrate **bytecode analysis** using `web3.py` to detect malicious
  behaviour even when the source code is not verified.
- Support **multiple chains** such as BNB Chain, Polygon or Base.
- Add a **Telegram bot** to send alerts when new suspicious contracts are
  deployed.
- Implement **honeypot simulation** (e.g., attempting to buy and sell via
  a router contract) as described in industry guides【933481489912976†L374-L399】.

## Usage

1. Install dependencies:

   ```sh
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r backend/requirements.txt
   ```

2. Définissez vos clés API :

   - Pour Ethereum : `ETHERSCAN_API_KEY`
   - Pour Binance Smart Chain (BSC) : `BSCSCAN_API_KEY` (facultatif ; si absent, la clé Ethereum sera utilisée)
   - Pour Polygon : `POLYGONSCAN_API_KEY` (facultatif)

   Vous pouvez les définir de deux façons :

   - En les exportant dans votre shell :

     ```sh
     export ETHERSCAN_API_KEY=YOUR_ETHERSCAN_KEY
     export BSCSCAN_API_KEY=YOUR_BSCSCAN_KEY   # optionnel
     export POLYGONSCAN_API_KEY=YOUR_POLYGON_KEY  # optionnel
     ```

   - Ou en créant un fichier `.env` à la racine du projet :

     ```env
     ETHERSCAN_API_KEY=YOUR_ETHERSCAN_KEY
     BSCSCAN_API_KEY=YOUR_BSCSCAN_KEY
     POLYGONSCAN_API_KEY=YOUR_POLYGON_KEY
     ```

   Le backend chargera automatiquement ces clés au démarrage via `python‑dotenv`.

3. Démarrez le serveur API pour le développement :

   ```sh
   uvicorn honeypot_detector.backend.main:app --reload
   ```

4. Soumettez un contrat à l’analyse via cURL ou la CLI :

   ```sh
   curl -X POST http://localhost:8000/analyze -H "Content-Type: application/json" \
     -d '{"address":"0x..."}'

   python -m honeypot_detector.backend.main 0x...
   ```

5. (Facultatif) Lancez l’interface web :

   ```sh
   cd frontend
   npm install
   npm run dev
   ```

   Ouvrez ensuite [http://localhost:5173](http://localhost:5173) dans votre navigateur. Le front‑end
   proxy les appels `/analyze` vers l’API à `localhost:8000`.

This project is provided for educational purposes and should not be
considered financial advice. Always perform your own due diligence
before interacting with tokens.