import React from "react";

export default function Badge({ risk }: { risk: "SAFE"|"MEDIUM"|"HIGH" }) {
  const map = {
    SAFE: "badge-safe",
    MEDIUM: "badge-medium",
    HIGH: "badge-high",
  } as const;
  return (
    <span className={`badge ${map[risk]}`}>
      <span className="w-2 h-2 rounded-full bg-current opacity-80" />
      {risk}
    </span>
  );
}
