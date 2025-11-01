import axios from "axios";

/**
 * Client API pour Honeypot Detector Pro.
 * - En dev : baseURL = "" → Vite proxy redirige /analyze vers http://localhost:8000
 * - En prod : définir VITE_API_BASE (ex: https://honeypot.yourdomain.com)
 */

export interface AnalysisReport {
  address: string;
  score: number;
  risk: "SAFE" | "MEDIUM" | "HIGH";
  flags: string[];
  summary: string;
}

const RAW_BASE = import.meta.env.VITE_API_BASE as string | undefined;
// On supprime un éventuel "/" final pour éviter "//analyze"
const BASE = (RAW_BASE || "").replace(/\/+$/, "");

// Instance axios (timeout + header JSON)
const api = axios.create({
  baseURL: BASE || undefined,
  timeout: 15000,
  headers: { "Content-Type": "application/json" },
});

/**
 * Analyse un contrat ERC-20 via le backend FastAPI.
 *
 * @param address Adresse du contrat à analyser (doit commencer par 0x).
 * @param chain   Réseau cible: "ethereum" | "bsc" | "polygon"
 * @returns       Rapport d’analyse (address, score, risk, flags, summary)
 */
export async function analyzeToken(address: string, chain: string): Promise<AnalysisReport> {
  try {
    const res = await api.post("/analyze", { address, chain });
    return res.data as AnalysisReport;
  } catch (err: any) {
    // Normalise un message d'erreur lisible pour l'UI
    const detail =
      err?.response?.data?.detail ||
      err?.message ||
      "Erreur inconnue lors de l’analyse";
    throw new Error(String(detail));
  }
}
