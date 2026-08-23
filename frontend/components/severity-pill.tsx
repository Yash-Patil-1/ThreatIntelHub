import type { Severity } from "@/lib/types";

// Spec-mandated severity colors.
export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#dc2626", // red-600
  high: "#ea580c", // orange-600
  medium: "#d97706", // amber-600
  low: "#16a34a", // green-600
  info: "#64748b", // slate-500
};

export function SeverityPill({ severity }: { severity: Severity }) {
  const c = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.info;
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium capitalize"
      style={{ color: c, borderColor: `${c}55`, backgroundColor: `${c}1a` }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: c }} />
      {severity}
    </span>
  );
}
