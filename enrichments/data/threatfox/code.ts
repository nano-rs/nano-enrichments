// ThreatFox IOC Feed — Bulk data enrichment
// Docs: https://threatfox.abuse.ch/api/

interface EnrichmentRecord {
  key: string;
  risk_score?: number;
  tags?: string[];
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

  const records: EnrichmentRecord[] = data.data.map((ioc: any) => {
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
      key: ioc.ioc_value,
      risk_score: risk,
      tags,
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
