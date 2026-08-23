export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type IocType = "ip" | "domain" | "url" | "hash";

export interface IocSummary {
  id: number;
  type: IocType;
  value_norm: string;
  threat_score: number;
  severity: Severity;
  last_seen?: string | null;
  sources: string[];
}

export interface ScoreSource {
  source: string;
  reliability_weight: number;
  hours_age: number;
  decay: number;
  contribution: number;
}

export interface ScoreBreakdown {
  per_source: ScoreSource[];
  cross_source_bonus: number;
  sighting_bonus: number;
  formula_version: string;
}

export interface Sighting {
  seen_at: string;
  source?: string | null;
}

export interface IocDetail extends IocSummary {
  first_seen?: string | null;
  score_breakdown: ScoreBreakdown;
  sightings: Sighting[];
  enrichments?: Record<string, unknown> | null;
}

export interface DashboardSummary {
  kpis: {
    total_iocs: number;
    by_severity: Partial<Record<Severity, number>>;
    active_feeds: number;
  };
  trend: { date: string; count: number }[];
  map: { country_code: string; count: number }[];
}
