import React, { useState, useEffect } from 'react';
import { analyzeToken } from './api';
import ReportCard from './components/ReportCard';

interface AnalysisResult {
  address: string;
  score: number;
  risk: string;
  flags: string[];
  summary: string;
}

/**
 * Composant principal de l’interface.
 *
 * Permet à l’utilisateur d’entrer une adresse de contrat, lance l’analyse via l’API
 * et affiche les résultats. Gère également un historique local des analyses précédentes.
 */
const App: React.FC = () => {
  const [address, setAddress] = useState('');
  const [network, setNetwork] = useState('ethereum');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<AnalysisResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Charger l’historique depuis localStorage au montage
  useEffect(() => {
    const stored = localStorage.getItem('hp_history');
    if (stored) {
      try {
        const parsed: AnalysisResult[] = JSON.parse(stored);
        setHistory(parsed);
      } catch {
        // ignore JSON parse error
      }
    }
  }, []);

  // Met à jour localStorage lorsqu’on modifie l’historique
  useEffect(() => {
    localStorage.setItem('hp_history', JSON.stringify(history));
  }, [history]);

  const handleAnalyze = async () => {
    // Validation simple de l’adresse
    const trimmed = address.trim();
    if (!/^0x[a-fA-F0-9]{40}$/.test(trimmed)) {
      setError('Adresse de contrat invalide');
      setResult(null);
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const res = await analyzeToken(trimmed, network);
      setResult(res);
      // Ajoute au début de l’historique, en supprimant les doublons
      setHistory((prev) => {
        const filtered = prev.filter((item) => item.address.toLowerCase() !== res.address.toLowerCase());
        const updated = [res, ...filtered];
        return updated.slice(0, 3);
      });
    } catch (err: any) {
      setError(err.message);
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  const handleHistoryClick = (item: AnalysisResult) => {
    setResult(item);
    setAddress(item.address);
    setError(null);
  };

  const handleDownload = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${result.address}_report.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-gray-50 py-10 px-4">
      <h1 className="text-3xl font-bold text-center mb-8">Honeypot Detector Pro</h1>
      <div className="max-w-xl mx-auto">
        {/* Sélection du réseau */}
        <div className="mb-4">
          <label htmlFor="network" className="block text-sm font-medium text-gray-700 mb-1">
            Réseau
          </label>
          <select
            id="network"
            value={network}
            onChange={(e) => setNetwork(e.target.value)}
            className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="ethereum">Ethereum</option>
            <option value="bsc">Binance Smart Chain</option>
            <option value="polygon">Polygon</option>
          </select>
        </div>
        <label htmlFor="address" className="block text-sm font-medium text-gray-700 mb-2">
          Adresse du contrat
        </label>
        <div className="flex items-center space-x-2">
          <input
            id="address"
            type="text"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            className="flex-grow border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="0x..."
          />
          <button
            onClick={handleAnalyze}
            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50"
            disabled={loading}
          >
            Analyser
          </button>
        </div>
        {error && <p className="text-red-600 mt-2">{error}</p>}
        {loading && <p className="mt-4 text-gray-600 animate-pulse">Analyse en cours...</p>}
      </div>
      {/* Historique des scans */}
      {history.length > 0 && (
        <div className="max-w-xl mx-auto mt-8">
          <h3 className="font-semibold mb-2">Historique des analyses</h3>
          <ul className="space-y-2 mb-3">
            {history.map((item) => (
              <li
                key={item.address}
                className="p-3 border rounded-md bg-white hover:bg-gray-100 cursor-pointer flex justify-between"
                onClick={() => handleHistoryClick(item)}
              >
                <span className="truncate" title={item.address}>{item.address}</span>
                <span className="font-medium">
                  {item.score} / 10
                </span>
              </li>
            ))}
          </ul>
          <button
            onClick={() => setHistory([])}
            className="text-sm text-blue-600 hover:underline"
          >
            Effacer l’historique
          </button>
        </div>
      )}
      {/* Résultat d’analyse */}
      {result && !loading && (
        <div className="max-w-2xl mx-auto mt-8">
          <ReportCard
            address={result.address}
            score={result.score}
            risk={result.risk}
            flags={result.flags}
            summary={result.summary}
          />
          <div className="text-right mt-4">
            <button
              onClick={handleDownload}
              className="bg-green-500 text-white px-4 py-2 rounded-md hover:bg-green-600"
            >
              Télécharger le rapport JSON
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;