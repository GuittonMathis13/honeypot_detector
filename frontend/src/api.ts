import axios from 'axios';

/**
 * Analyse un contrat ERC‑20 via le backend FastAPI.
 *
 * @param address Adresse du contrat à analyser (doit commencer par 0x).
 * @returns Un objet avec les champs address, score, risk, flags et summary.
 */
export async function analyzeToken(address: string, chain: string) {
  try {
    const response = await axios.post('/analyze', { address, chain });
    return response.data as {
      address: string;
      score: number;
      risk: string;
      flags: string[];
      summary: string;
    };
  } catch (error: any) {
    // Propager une erreur lisible pour l’interface utilisateur
    if (error.response?.data?.detail) {
      throw new Error(error.response.data.detail);
    }
    throw new Error('Erreur inconnue lors de l’analyse');
  }
}
