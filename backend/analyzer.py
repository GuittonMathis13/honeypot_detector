"""
    analyzer.py — core analysis logic (Etherscan API v2, multichain via chainid)

    - Utilise UN SEUL endpoint: https://api.etherscan.io/v2/api
    - Passe la chaîne via ?chainid=1|56|137 (Ethereum/BSC/Polygon)
    - Suivi des proxys (Proxy/Implementation) + flag proxy_pattern
    - Parsing robuste: result peut être list/dict; fallback si message contient
      du code
"""

from __future__ import annotations
import os
import re
from typing import Dict, Tuple, Optional

import requests

from . import rules
from . import report

HDP_DEBUG = os.getenv("HDP_DEBUG") == "1"


class ContractAnalyzer:
    """
    Fetch & analyze contract source code from Etherscan API v2.
    A single Etherscan V2 API key can cover multiple chains by passing `chainid`.
    """

    # Chaînes supportées → chainid
    CHAIN_IDS: Dict[str, str] = {
        "ethereum": "1",
        "bsc": "56",
        "polygon": "137",
    }

    ETHERSCAN_V2_BASE = "https://api.etherscan.io/v2/api"

    def __init__(self, api_key: Optional[str] = None, chain: str = "ethereum") -> None:
        chain = (chain or "ethereum").lower()
        if chain not in self.CHAIN_IDS:
            chain = "ethereum"
        self.chain = chain
        self.chain_id = self.CHAIN_IDS[chain]

        # On privilégie une clé dédiée à la chaîne si dispo,
        # sinon on prend ETHERSCAN_API_KEY (clé V2 multichaîne).
        env_key_name = {
            "ethereum": "ETHERSCAN_API_KEY",
            "bsc": "BSCSCAN_API_KEY",
            "polygon": "POLYGONSCAN_API_KEY",
        }.get(chain, "ETHERSCAN_API_KEY")

        self.api_key = api_key or os.getenv(env_key_name) or os.getenv("ETHERSCAN_API_KEY", "")
        self.api_base = self.ETHERSCAN_V2_BASE

        # flag interne pour marquer un proxy (si on a dû suivre Implementation)
        self._last_proxy = False

    # ------------------------ utils internes ------------------------

    def _validate_address(self, address: str) -> None:
        if not re.fullmatch(r"0x[a-fA-F0-9]{40}", address):
            raise ValueError(f"Invalid contract address: {address}")

    def _http_get(self, params: Dict[str, str]) -> Optional[dict]:
        if HDP_DEBUG:
            print(f"[HDP] GET {self.api_base} params={params}")
        try:
            r = requests.get(self.api_base, params=params, timeout=15)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if HDP_DEBUG:
                print(f"[HDP] HTTP error: {e}")
            return None

    def _extract_entry_and_source(self, data: dict) -> Tuple[Optional[dict], str]:
        """
        Etherscan V2 success:
          { "status":"1","message":"OK","result":[{...}] }  (souvent list)
        Parfois `result` est un dict. On supporte les deux.
        Si `result` est vide mais `message` contient clairement du code,
        on considère `message` comme source (fallback).
        """
        status = str(data.get("status", "0"))
        if status != "1":
            return None, ""

        res = data.get("result")
        if isinstance(res, list) and res:
            entry = res[0]
        elif isinstance(res, dict) and res:
            entry = res
        else:
            entry = None

        # source principal dans SourceCode/Sourcecode
        source = ""
        if entry:
            source = (entry.get("SourceCode") or entry.get("Sourcecode") or "").strip()

        if not source:
            # Fallback: parfois v2 renvoie du code directement dans "message"
            msg = (data.get("message") or "").strip()
            if any(x in msg for x in ("pragma solidity", "contract ", "library ", "interface ")):
                source = msg

        return entry, source

    def _fetch_source_v2(self, address: str) -> Tuple[str, bool]:
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "chainid": self.chain_id,   # ← INDISPENSABLE en v2
            "apikey": self.api_key,     # ← clé v2 (multi-chaîne possible)
        }
        data = self._http_get(params)
        if not data:
            return "", False

        # Cas clés invalides, quotas, etc.
        if str(data.get("status", "0")) != "1":
            result_msg = data.get("result")
            msg = result_msg if isinstance(result_msg, str) else data.get("message", "")
            if isinstance(msg, str) and "invalid api" in msg.lower():
                raise ValueError(f"Invalid API key for chain {self.chain}: {msg}")
            if HDP_DEBUG:
                print(f"[HDP] Non-OK response: {data}")
            return "", False

        entry, source = self._extract_entry_and_source(data)

        # Si pas de source et que c’est un proxy → suivre Implementation
        if (not source) and entry and (
            entry.get("Proxy") == "1" or str(entry.get("IsProxy", "")).lower() in ("1", "true")
        ):
            impl = entry.get("Implementation") or entry.get("Implementation Address")
            if impl and isinstance(impl, str) and impl.lower().startswith("0x"):
                self._last_proxy = True
                if HDP_DEBUG:
                    print(f"[HDP] Following implementation {impl}")
                impl_source, impl_ok = self._fetch_source_v2(impl)
                return impl_source, impl_ok

        return source, bool(source)

    # -------------------------- API publique --------------------------

    def get_source_code(self, address: str) -> Tuple[str, bool]:
        # v2 uniquement (le wrapper etherscan-python est V1).
        return self._fetch_source_v2(address)

    def analyze_contract(self, address: str) -> Dict[str, object]:
        self._validate_address(address)
        source_code, source_available = self.get_source_code(address)

        flags = rules.run_all_checks(source_code or "", source_available)
        if self._last_proxy:
            flags["proxy_pattern"] = True
        self._last_proxy = False

        return report.build_report(address=address, flags=flags)
