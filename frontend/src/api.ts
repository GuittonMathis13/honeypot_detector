import axios from "axios";

/**
 * Analyse un contrat ERC-20 via le backend FastAPI.
 */
export async function analyzeToken(address: string, chain: string) {
  try {
    const base = import.meta.env.PROD
      ? (import.meta.env.VITE_API_BASE ?? "")
      : "";
    const response = await axios.post(`${base}/analyze`, { address, chain });
    return response.data as {
      address: string;
      score: number;
      risk: "SAFE" | "MEDIUM" | "HIGH";
      flags: string[];
      summary: string;
    };
  } catch (error: any) {
    if (error.response?.data?.detail) {
      throw new Error(error.response.data.detail);
    }
    throw new Error("Erreur inconnue lors de l’analyse");
  }
}
