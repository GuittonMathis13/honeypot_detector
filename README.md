# Honeypot Detector Pro

> **Statut v1.0.0 (POC)** — Outil d’analyse **statique** de tokens ERC-20 (ETH / BSC / Polygon).  
> Récupère le code source via **Etherscan v2** (avec `chainid`), suit les **proxys** (Implementation), applique des **règles heuristiques**, calcule un **score 0–10** et un **verdict** (SAFE / MEDIUM / HIGH).  
> Idéal portfolio/screening. Non déterministe à 100 % (dépend des explorers & de la vérification de code).

---

##  Fonctionnalités

- **Backend (FastAPI + CLI)**  
  - Etherscan v2 multi-chain (`chainid` = 1, 56, 137)  
  - Suivi **Proxy → Implementation** + flag `proxy_pattern`  
  - Heuristiques : `modifiable_fee`, `blacklist_whitelist`, `uniswap_restriction`, `minting`, `pause_trading`, `transfer_limits`, `dynamic_fees_public`, `transfer_trap`, `max_limits_strict`, `proxy_pattern`, `unverified_code`  
  - Scoring 0–10 + verdict + résumé

- **Frontend (React / Vite / Tailwind)**  
  - Input adresse + réseau → appel API  
  - Loader, rapport, **historique local** (5 derniers), copier adresse, lien explorer

- **Tests** : règles & scoring (pytest)

---

##  Stack

- **Backend** : Python, FastAPI, Uvicorn, Requests, Pytest  
- **Frontend** : React 18, Vite, TypeScript, Tailwind, Axios

---

## 📦 Structure
.
├─ .github/workflows/
│ ├─ backend.yml
│ └─ frontend.yml
├─ backend/
│ ├─ init.py
│ ├─ analyzer.py
│ ├─ main.py
│ ├─ report.py
│ ├─ requirements.txt
│ └─ rules.py
├─ frontend/
│ ├─ index.html
│ ├─ package.json
│ ├─ vite.config.ts
│ ├─ postcss.config.cjs
│ ├─ tailwind.config.cjs
│ └─ src/...
├─ example_reports/
│ ├─ SafeToken.json
│ └─ ScamToken.json
├─ tests/
│ └─ test_analyzer.py
├─ cli.py
├─ LICENSE
├─ README.md
└─ .gitignore


---

## ⚙️ Installation & Lancement

### Backend (dev)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Clés API (Etherscan v2)
export ETHERSCAN_API_KEY="xxxxx"     # couvre multi-chain en v2
export BSCSCAN_API_KEY="(optionnel)"
export POLYGONSCAN_API_KEY="(optionnel)"

uvicorn main:app --reload
# → http://127.0.0.1:8000

Endpoint
POST /analyze
{ "address": "0x...", "chain": "ethereum|bsc|polygon" }

CLI (analyse directe)
cd backend
python main.py 0xA0b8... --chain ethereum

Frontend (dev)
cd frontend
npm install
npm run dev
# → http://localhost:5173

Tests
pytest -v --maxfail=1 --disable-warnings

Scoring (rappel)

Poids par drapeau (simplifié) — report.py :

fort : blacklist/whitelist, dynamic fees + setters, transfer limits, transfer trap

moyen : proxy_pattern, minting, pause trading

faible : max_limits_strict

bonus : unverified_code si aucun code source

Un stablecoin peut sortir HIGH (centralisation : pause/blacklist/owner).
Ce n’est pas “scam automatique”, c’est un risque de contrôle.

Roadmap courte

Catégories de risque (Centralisation / Tokenomics / Suspicious) dans la réponse JSON

Renonciation “réelle” (events + storage, Ownable/Ownable2Step)

Bytecode fallback (web3.py) si pas de source

Checks DeFi/LP (verrouillage, owner du pair)

Cache + retries pour limiter unverified_code (quota/ratés explorer)

Disclaimer
Outil d’analyse statique à but éducatif.
Ne constitue pas un conseil financier. Vérifiez toujours sur chain/explorer.