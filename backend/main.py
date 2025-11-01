"""
main.py
Entry point for the Honeypot Detector Pro backend.
It exposes a FastAPI application with a single endpoint `/analyze`
and also supports execution as a standalone CLI tool.

Usage examples:
    # 1️⃣ Lancer le serveur API (mode dev)
    uvicorn backend.main:app --reload

    # 2️⃣ Analyser un contrat depuis le terminal
    python -m backend.main 0xABCDEF... --chain ethereum
    # ou plus simple :
    ./cli.py 0xABCDEF... --chain bsc

Environment variables:
    ETHERSCAN_API_KEY – clé API Etherscan (Multi-chain V2)
"""

from __future__ import annotations
import sys
import json
import argparse
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, constr
from colorama import Fore, Style, init as color_init

# Optionnel : support .env local
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

from backend.analyzer import ContractAnalyzer


# ----------------------------- #
#   ⚙️  FastAPI Initialisation
# ----------------------------- #

class AnalyzeRequest(BaseModel):
    address: constr(strip_whitespace=True)
    chain: str | None = "ethereum"


app = FastAPI(
    title="Honeypot Detector Pro",
    description="Analyse des contrats ERC-20 pour détecter les honeypots et risques.",
    version="1.0.0",
)


@app.post("/analyze")
async def analyze(request: AnalyzeRequest) -> Any:
    """Analyse une adresse de contrat et renvoie un rapport structuré."""
    address = request.address
    chain = (request.chain or "ethereum").lower()

    try:
        analyzer = ContractAnalyzer(chain=chain)
        report_data = analyzer.analyze_contract(address)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur interne: {exc}")
    return report_data


# ----------------------------- #
#   🧠  Mode CLI (terminal)
# ----------------------------- #

def _cli_print_report(report_data: dict) -> None:
    """Affiche joliment le rapport dans le terminal (avec couleurs)."""
    color_init(autoreset=True)
    risk_color = {
        "SAFE": Fore.GREEN,
        "MEDIUM": Fore.YELLOW,
        "HIGH": Fore.RED,
    }.get(report_data["risk"], Fore.WHITE)

    print(f"\nContract: {report_data['address']}")
    print(f"Score: {report_data['score']}/10")
    print(f"Risk: {risk_color}{report_data['risk']}{Style.RESET_ALL}")

    if report_data.get("flags"):
        print("Flags:")
        for flag in report_data["flags"]:
            print(f"  - {flag}")
    print(f"Summary: {report_data['summary']}\n")


def cli():
    """Entrée principale pour le CLI (utilisé par cli.py)."""
    parser = argparse.ArgumentParser(description="Analyse un contrat ERC-20 pour détecter les honeypots.")
    parser.add_argument("address", help="Adresse du contrat à analyser")
    parser.add_argument("--chain", choices=["ethereum", "bsc", "polygon"], default="ethereum", help="Blockchain cible")
    parser.add_argument("--out", type=str, help="Sauvegarde le rapport au format JSON")
    args = parser.parse_args()

    try:
        analyzer = ContractAnalyzer(chain=args.chain)
        report_data = analyzer.analyze_contract(args.address)
    except Exception as exc:
        print(f"❌ Erreur: {exc}")
        sys.exit(1)

    # Sauvegarde optionnelle
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
            print(f"📁 Rapport sauvegardé dans {args.out}")
        except Exception as exc:
            print(f"⚠️  Erreur lors de la sauvegarde: {exc}")

    _cli_print_report(report_data)


if __name__ == "__main__":
    cli()
