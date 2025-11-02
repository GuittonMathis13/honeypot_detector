import React from "react";
import Badge from "./Badge";

type Report = {
  address: string;
  score: number;
  risk: "SAFE" | "MEDIUM" | "HIGH";
  flags: string[];
  summary: string;
};

const FLAG_LABELS: Record<string, string> = {
  modifiable_fee: "Fees modifiables",
  blacklist_whitelist: "Blacklist/Whitelist",
  uniswap_restriction: "Restriction LP",
  owner_not_renounced: "Propriété active",
  minting: "Mint possible",
  pause_trading: "Pause trading",
  unverified_code: "Code non vérifié",
  transfer_limits: "Limites transfert/portefeuille",
  proxy_pattern: "Pattern Proxy/Delegatecall",
  max_limits_strict: "Limites très strictes (≤2%)",
  dynamic_fees_public: "Taxes dynamiques publiques",
  transfer_trap: "Piège transfert (owner)",
};

export default function ReportCard({ report, onCopy, onOpenScan }: {
  report: Report;
  onCopy: (addr: string) => void;
  onOpenScan: (addr: string) => void;
}) {
  const pct = Math.round((report.score / 10) * 100);

  return (
    <div className="card p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold">Rapport d’analyse</h2>
          <p className="muted text-sm">{report.address}</p>
        </div>
        <Badge risk={report.risk} />
      </div>

      <div className="mt-4">
        <div className="flex items-center justify-between text-sm mb-1">
          <span className="muted">Score de risque</span>
          <span className="font-semibold">{report.score}/10</span>
        </div>
        <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
          <div
            className={`h-full transition-all ${
              report.risk === "HIGH" ? "bg-rose-500"
              : report.risk === "MEDIUM" ? "bg-amber-400"
              : "bg-emerald-400"
            }`}
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      <div className="mt-4 space-y-2">
        <h3 className="text-sm font-semibold">Drapeaux détectés</h3>
        <div className="flex flex-wrap gap-2">
          {report.flags.length ? report.flags.map((f) => (
            <span key={f} className="badge border-slate-700 text-slate-200 bg-slate-800/60">
              {FLAG_LABELS[f] ?? f}
            </span>
          )) : (
            <span className="muted">Aucun drapeau significatif.</span>
          )}
        </div>
      </div>

      <p className="mt-4 text-sm leading-relaxed text-slate-300">
        {report.summary}
      </p>

      <div className="mt-5 flex flex-wrap items-center gap-2">
        <button className="btn" onClick={() => onCopy(report.address)}>Copier l’adresse</button>
        <button className="btn" onClick={() => onOpenScan(report.address)}>Ouvrir sur Etherscan</button>
      </div>
    </div>
  );
}
