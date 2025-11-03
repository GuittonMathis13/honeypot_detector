import React, { useMemo, useState } from "react";
import Spinner from "./components/Spinner";
import ReportCard from "./components/ReportCard";
import { analyzeToken } from "./api";

type Saved = {
  when: string; // ISO
  address: string;
  chain: string;
  report: any;
};

export default function App() {
  const [address, setAddress] = useState("");
  const [chain, setChain] = useState<"ethereum" | "bsc" | "polygon">("ethereum");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<any | null>(null);

  const [history, setHistory] = useState<Saved[]>(() => {
    try {
      const raw = localStorage.getItem("hpdetector:history");
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
    }
  });

  const canSubmit = useMemo(
    () => address.trim().startsWith("0x") && address.trim().length === 42,
    [address],
  );

  function saveHistory(entry: Saved) {
    const next = [entry, ...history].slice(0, 5);
    setHistory(next);
    localStorage.setItem("hpdetector:history", JSON.stringify(next));
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    setReport(null);
    try {
      const rep = await analyzeToken(address.trim(), chain);
      setReport(rep);
      saveHistory({ when: new Date().toISOString(), address: address.trim(), chain, report: rep });
    } catch (err: any) {
      setError(err.message ?? "Erreur inconnue");
    } finally {
      setLoading(false);
    }
  }

  function handleCopy(addr: string) {
    navigator.clipboard.writeText(addr).catch(() => {});
  }

  function handleOpenScan(addr: string) {
    const map: Record<string, string> = {
      ethereum: "https://etherscan.io/address/",
      bsc: "https://bscscan.com/address/",
      polygon: "https://polygonscan.com/address/",
    };
    window.open(`${map[chain]}${addr}`, "_blank");
  }

  return (
    <div className="min-h-full text-slate-100">
      <header className="px-6 py-5">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <h1 className="text-2xl font-bold tracking-tight">Honeypot Detector Pro</h1>
          <div className="text-xs text-slate-400">v1.0 • Dark-Ops</div>
        </div>
      </header>

      <main className="px-6 pb-12">
        <div className="max-w-4xl mx-auto grid md:grid-cols-3 gap-6">
          <section className="md:col-span-2 card p-5">
            <form onSubmit={onSubmit} className="space-y-4">
              <div className="grid sm:grid-cols-5 gap-3">
                <div className="sm:col-span-4">
                  <label className="text-sm muted">Adresse du contrat</label>
                  <input
                    className="input mt-1"
                    placeholder="0x…"
                    value={address}
                    onChange={(e) => setAddress(e.target.value)}
                  />
                </div>
                <div className="sm:col-span-1">
                  <label className="text-sm muted">Réseau</label>
                  <select
                    className="input mt-1"
                    value={chain}
                    onChange={(e) => setChain(e.target.value as any)}
                  >
                    <option value="ethereum">Ethereum</option>
                    <option value="bsc">BSC</option>
                    <option value="polygon">Polygon</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button className="btn" disabled={!canSubmit || loading}>
                  {loading ? <Spinner /> : "Analyser"}
                </button>
                {!canSubmit && <span className="text-xs text-rose-300">Adresse invalide</span>}
              </div>
            </form>

            {error && (
              <div className="mt-4 border border-rose-700 bg-rose-900/20 rounded-xl px-4 py-3 text-sm">
                {error}
              </div>
            )}

            {loading && !error && (
              <div className="mt-6 card p-6">
                <div className="flex items-center gap-3">
                  <Spinner />
                  <div>
                    <div className="font-medium">Analyse en cours…</div>
                    <div className="muted text-sm">Contact du backend et exécution des heuristiques</div>
                  </div>
                </div>
              </div>
            )}

            {report && !loading && !error && (
              <div className="mt-6">
                <ReportCard report={report} onCopy={handleCopy} onOpenScan={handleOpenScan} />
              </div>
            )}
          </section>

          <aside className="card p-5">
            <h3 className="text-sm font-semibold mb-3">Historique (5 derniers)</h3>
            <div className="space-y-3">
              {history.length ? (
                history.map((h, i) => (
                  <div key={i} className="rounded-xl border border-slate-800 p-3 bg-slate-900/60">
                    <div className="text-xs muted">{new Date(h.when).toLocaleString()}</div>
                    <div className="text-sm font-mono truncate">{h.address}</div>
                    <div className="flex items-center gap-2 mt-2">
                      <button
                        className="btn text-xs"
                        onClick={() => {
                          setAddress(h.address);
                          setChain(h.chain as any);
                          setReport(h.report);
                        }}
                      >
                        Charger
                      </button>
                      <button className="btn text-xs" onClick={() => navigator.clipboard.writeText(h.address)}>
                        Copier
                      </button>
                    </div>
                  </div>
                ))
              ) : (
                <div className="muted text-sm">Aucun historique pour l’instant.</div>
              )}
            </div>

            <button
              className="btn w-full mt-4"
              onClick={() => {
                setHistory([]);
                localStorage.removeItem("hpdetector:history");
              }}
            >
              Effacer l’historique
            </button>
          </aside>
        </div>
      </main>
    </div>
  );
}
