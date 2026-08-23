"use client";

import { useMemo } from "react";
import { ComposableMap, Geographies, Geography } from "react-simple-maps";
import { ALPHA2_TO_NUMERIC } from "@/lib/country-codes";

interface CountryCount {
  country_code: string;
  count: number;
}

// slate-800 base → cyan-400 hot
const BASE = [30, 41, 59]; // #1e293b
const HOT = [34, 211, 238]; // #22d3ee

function colorFor(count: number, max: number): string {
  if (count <= 0) return `rgb(${BASE.join(",")})`;
  // gamma 0.5 so low-count countries are still distinguishable
  const t = Math.sqrt(Math.min(1, count / Math.max(1, max)));
  const rgb = BASE.map((b, i) => Math.round(b + (HOT[i] - b) * t));
  return `rgb(${rgb.join(",")})`;
}

export default function DashboardMap({ data }: { data: CountryCount[] }) {
  const byNumeric = useMemo(() => {
    const m = new Map<string, number>();
    for (const d of data) {
      const num = ALPHA2_TO_NUMERIC[String(d.country_code).toUpperCase()];
      if (num) m.set(num, d.count);
    }
    return m;
  }, [data]);
  const max = Math.max(1, ...data.map((d) => d.count));

  return (
    <ComposableMap projectionConfig={{ scale: 147 }} className="h-auto w-full">
      <Geographies geography="https://unpkg.com/world-atlas@2/countries-110m.json">
        {({ geographies }: { geographies: Array<{ rsmKey: string; id?: string | number }> }) =>
          geographies.map((geo) => (
            <Geography
              key={geo.rsmKey}
              geography={geo}
              fill={colorFor(byNumeric.get(String(geo.id)) ?? 0, max)}
              stroke="#0f172a"
              strokeWidth={0.4}
            />
          ))
        }
      </Geographies>
    </ComposableMap>
  );
}
