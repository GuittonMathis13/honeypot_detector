# Honeypot Detector Pro

Outil **Web3 / sécurité** d’analyse **statique** de tokens **ERC-20** (Ethereum / BSC / Polygon).
Il récupère le code via **Etherscan v2 (chainid)**, suit les **proxys → Implementation**, applique des règles heuristiques, puis produit un **score 0–10** et un **verdict** (**SAFE / MEDIUM / HIGH**) avec un résumé lisible.

> Objectif : aider au **screening rapide** d’un token avant interaction (achat, LP, approval), en complément d’une vérification manuelle.

---

## Ce que fait le projet

### Backend (FastAPI + CLI)

* Récupération du code source via **Etherscan v2** (multi-chain)
* Détection **Proxy → Implementation** + flag `proxy_pattern`
* Règles heuristiques (flags) :

  * `modifiable_fee`, `blacklist_whitelist`, `uniswap_restriction`
  * `minting`, `pause_trading`, `transfer_limits`, `dynamic_fees_public`
  * `transfer_trap`, `max_limits_strict`, `proxy_pattern`, `unverified_code`
* **Scoring 0–10** + **verdict** + **résumé** (rapport JSON)

### Frontend (React / Vite / Tailwind)

* Input **adresse + réseau** → appel API
* Loader, affichage rapport, **historique local (5 derniers)**, copier adresse, lien explorer

### Tests

* Tests des règles & du scoring (**pytest**)

---

## Stack

* **Backend** : Python, FastAPI, Uvicorn, Requests, Pytest
* **Frontend** : React 18, Vite, TypeScript, Tailwind, Axios

---

## Structure du repo

```txt
.
├─ .github/workflows/
│  ├─ backend.yml
│  └─ frontend.yml
├─ backend/
│  ├─ __init__.py
│  ├─ analyzer.py
│  ├─ main.py
│  ├─ report.py
│  ├─ requirements.txt
│  └─ rules.py
├─ frontend/
│  ├─ index.html
│  ├─ package.json
│  ├─ vite.config.ts
│  ├─ postcss.config.cjs
│  ├─ tailwind.config.cjs
│  └─ src/...
├─ example_reports/
│  ├─ SafeToken.json
│  └─ ScamToken.json
├─ tests/
│  └─ test_analyzer.py
├─ cli.py
├─ LICENSE
└─ README.md
```

---

## Démarrage rapide

### 1) Backend (dev)

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Clés API (Etherscan v2)

Le backend utilise **Etherscan v2**.

```bash
export ETHERSCAN_API_KEY="xxxxx"     # recommandé (couvre multi-chain en v2)
export BSCSCAN_API_KEY="xxxxx"       # optionnel
export POLYGONSCAN_API_KEY="xxxxx"   # optionnel
```

### Lancer l’API

```bash
uvicorn main:app --reload
```

Accès : [http://127.0.0.1:8000](http://127.0.0.1:8000)

---

### 2) Frontend (dev)

```bash
cd frontend
npm install
npm run dev
```

Accès : [http://localhost:5173](http://localhost:5173)

---

## API

**POST** `/analyze`

Body :

```json
{ "address": "0x...", "chain": "ethereum|bsc|polygon" }
```

Réponse : rapport JSON incluant score, verdict et flags déclenchés.

---

## CLI

Analyse directe depuis le backend :

```bash
cd backend
python main.py 0xA0b8... --chain ethereum
```

---

## Scoring & interprétation

Le score **n’est pas une preuve de scam** : il représente un **niveau de risque** (contrôle, restrictions, comportements suspects).

Exemple : un stablecoin peut sortir **HIGH** (centralisation : pause / blacklist / owner).

Rappel des poids (simplifié, voir `backend/report.py`) :

* **Fort** : blacklist/whitelist, dynamic fees + setters, transfer limits, transfer trap
* **Moyen** : proxy_pattern, minting, pause trading
* **Faible** : max_limits_strict
* `unverified_code` si aucun code source récupérable

---

## Tests

```bash
pytest -v --maxfail=1 --disable-warnings
```

Le dossier `example_reports/` contient des rapports JSON prêts à consulter :

* `SafeToken.json`
* `ScamToken.json`

---

## Limites

* Analyse **statique uniquement** : ne remplace pas une vérification on-chain, la lecture du code ou une simulation.
* Dépendance aux explorers (quotas, indisponibilités, code non vérifié).
* Certains tokens "légitimes" peuvent être classés à risque élevé.

---

Outil d’analyse statique à but éducatif.
Vérifiez toujours **on-chain / explorer**.
