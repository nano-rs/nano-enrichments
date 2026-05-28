// ThreatFox IOC Feed — Bulk data enrichment
// Docs: https://threatfox.abuse.ch/api/

interface EnrichmentRecord {
  key: string;
  risk_score?: number;
  tags?: string[];
  // IOC-typed columns that nanosiem's Rust scheduler reads at the top level
  // and writes into dedicated ClickHouse columns. Required for IOC data
  // enrichments (NAN-1105). Without these the per-IOC columns stay blank
  // and the ReplacingMergeTree-backed results table collapses every row
  // with key_value="" into one dedup-survivor.
  threat_type?: string;
  malware?: string;
  confidence?: number;
  data: Record<string, unknown>;
}

interface DataEnrichmentResult {
  records: EnrichmentRecord[];
  watermark?: string;
}

async function enrich(context: {
  lastWatermark?: string;
  credentials: Record<string, string>;
}): Promise<DataEnrichmentResult> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (context.credentials.API_KEY) {
    headers["Auth-Key"] = context.credentials.API_KEY;
  }

  // Fetch recent IOCs (last 7 days or since watermark)
  const days = context.lastWatermark ? 1 : 7;

  const res = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers,
    body: JSON.stringify({ query: "get_iocs", days }),
  });

  if (!res.ok) throw new Error(`ThreatFox API error: ${res.status}`);
  const data = await res.json();

  if (data.query_status !== "ok" || !data.data) {
    return { records: [], watermark: new Date().toISOString() };
  }

  const records: EnrichmentRecord[] = data.data
    // Drop records missing the IOC value rather than emitting `key=""` rows.
    // The whole NAN-1105 regression was caused by undefined keys collapsing
    // under ReplacingMergeTree; defending against future schema drift here
    // makes the same shape stay loud (records_fetched drops) instead of
    // silently re-creating that bug.
    .filter((ioc: any) => typeof ioc.ioc === "string" && ioc.ioc.length > 0)
    .map((ioc: any) => {
      const tags: string[] = [];
      if (ioc.threat_type) tags.push(ioc.threat_type);
      if (ioc.malware) tags.push(ioc.malware);
      if (ioc.tags) tags.push(...ioc.tags);

      // Confidence level maps to risk
      const risk =
        ioc.confidence_level >= 75
          ? 90
          : ioc.confidence_level >= 50
            ? 70
            : 50;

      return {
        // The abuse.ch ThreatFox API v1 response field for the IOC value is
        // `ioc`, not `ioc_value`. The previous code read a non-existent
        // field so every row landed with key_value="" and ReplacingMergeTree
        // collapsed thousands of IOCs into one (NAN-1105).
        key: ioc.ioc,
        risk_score: risk,
        tags,
        // Top-level IOC fields populate the dedicated ClickHouse columns.
        // `confidence` is read by Rust as u64 -> u8; an undefined value here
        // becomes confidence=0 downstream, which is indistinguishable from a
        // legitimate `confidence_level=0` row — analyst tooling should treat
        // 0 as "low or unknown" rather than a strict floor.
        threat_type: ioc.threat_type,
        malware: ioc.malware,
        confidence: ioc.confidence_level,
        // `data` intentionally duplicates threat_type/malware/confidence so
        // existing dashboards and notebooks that read `data.threat_type`
        // keep working. Removing the duplicates is a breaking change for
        // downstream consumers; don't simplify without auditing them first.
        data: {
          ioc_type: ioc.ioc_type,
          threat_type: ioc.threat_type,
          malware: ioc.malware,
          confidence: ioc.confidence_level,
          reporter: ioc.reporter,
          reference: ioc.reference,
          first_seen: ioc.first_seen_utc,
          last_seen: ioc.last_seen_utc,
        },
      };
    });

  return {
    records,
    watermark: new Date().toISOString(),
  };
}

export { enrich };
