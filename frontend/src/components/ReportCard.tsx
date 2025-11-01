import React from 'react';
import {
  FaCheckCircle,
  FaExclamationTriangle,
  FaTimesCircle,
  FaFlag,
  FaMoneyBillWave,
  FaBan,
  FaShoppingCart,
  FaUserShield,
  FaCoins,
  FaPauseCircle,
  FaQuestionCircle,
  FaHandPaper,
  FaProjectDiagram,
} from 'react-icons/fa';

interface ReportCardProps {
  address: string;
  score: number;
  risk: string;
  flags: string[];
  summary: string;
}

/**
 * Carte d’affichage des résultats d’analyse.
 *
 * Présente le score, la catégorie de risque, les flags détectés et un résumé.
 */
const ReportCard: React.FC<ReportCardProps> = ({ address, score, risk, flags, summary }) => {
  // Déterminer la couleur et l’icône selon la catégorie de risque
  let barColor = 'bg-green-500';
  let RiskIcon: React.ElementType = FaCheckCircle;
  let riskLabel = 'Safe';
  if (score >= 4 && score <= 6) {
    barColor = 'bg-yellow-400';
    RiskIcon = FaExclamationTriangle;
    riskLabel = 'Medium';
  } else if (score >= 7) {
    barColor = 'bg-red-500';
    RiskIcon = FaTimesCircle;
    riskLabel = 'High';
  }

  // Calcule la largeur de la barre (%)
  const barWidth = `${Math.min(100, Math.max(0, (score / 10) * 100))}%`;

  return (
    <div className="mt-6 p-6 rounded-lg shadow-md bg-white max-w-2xl mx-auto">
      <h2 className="text-2xl font-bold mb-4">Résultat d’analyse</h2>
      <p className="text-sm text-gray-600 break-all mb-4">Adresse analysée : {address}</p>
      <div className="mb-4">
        <div className="flex items-center mb-2">
          <RiskIcon className="mr-2 text-xl" />
          <span className="text-xl font-semibold">
            Score : {score} / 10 — {riskLabel} Risk
          </span>
        </div>
        <div className="w-full h-4 bg-gray-200 rounded-full overflow-hidden">
          <div className={`${barColor} h-full`} style={{ width: barWidth }} />
        </div>
      </div>
      {flags.length > 0 && (
        <div className="mb-4">
          <h3 className="font-semibold mb-2">Flags détectés :</h3>
          <ul className="list-none space-y-1">
            {flags.map((flag) => {
              // Map flag to an icon and description
              const ICON_MAP: Record<string, React.ElementType> = {
                modifiable_fee: FaMoneyBillWave,
                blacklist_whitelist: FaBan,
                uniswap_restriction: FaShoppingCart,
                owner_not_renounced: FaUserShield,
                minting: FaCoins,
                pause_trading: FaPauseCircle,
                unverified_code: FaQuestionCircle,
                transfer_limits: FaHandPaper,
                proxy_pattern: FaProjectDiagram,
              };
              const DESC_MAP: Record<string, string> = {
                modifiable_fee: 'Contract allows tax or fee parameters to be modified by privileged accounts.',
                blacklist_whitelist: 'Contract contains blacklist/whitelist or transfer restrictions that can block users.',
                uniswap_restriction: 'Contract restricts selling via the liquidity pool (potential honeypot).',
                owner_not_renounced: 'Ownership is active and onlyOwner functions exist without renunciation.',
                minting: 'Mint function detected – supply can be increased at will.',
                pause_trading: 'Trading can be paused or resumed by the owner.',
                unverified_code: 'Source code is unverified; logic cannot be audited.',
                transfer_limits: 'Contract imposes maximum transaction or wallet limits, which can restrict users from selling or transferring.',
                proxy_pattern: 'Contract uses delegatecall or proxy pattern; logic may be upgraded after deployment.',
              };
              const Icon = ICON_MAP[flag] || FaFlag;
              const description = DESC_MAP[flag] || '';
              return (
                <li key={flag} className="flex items-center" title={description}>
                  <Icon className="text-red-500 mr-2" />
                  <span className="capitalize">{flag.replace(/_/g, ' ')}</span>
                </li>
              );
            })}
          </ul>
        </div>
      )}
      <div>
        <h3 className="font-semibold mb-2">Résumé :</h3>
        <p className="text-gray-700 leading-relaxed">{summary}</p>
      </div>
    </div>
  );
};

export default ReportCard;