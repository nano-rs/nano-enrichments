// One mock for every enrichment vendor (NAN-3490 shadow runs). SYNTHETIC
// DATA. Routes on the vendor host (`x-mock-host`) and path, and checks each
// vendor's auth the way the vendor does, so a script and a spec that send the
// key differently both fail rather than both pass.

import { json, mockHost } from "./lib.ts";

const vtAttrs = (extra: Record<string, unknown>) => ({
  data: {
    attributes: {
      last_analysis_stats: { malicious: 12, suspicious: 3, undetected: 50, harmless: 5 },
      tags: ["peexe", "signed"],
      reputation: -20,
      categories: { Forcepoint: "malicious" },
      popular_threat_classification: { suggested_threat_label: "trojan.emotet/x" },
      last_analysis_date: 1_760_000_000,
      ...extra,
    },
  },
});

const vtUrlId = btoa("http://evil.example/x?y=1").replace(/=+$/, "");

export async function enrichmentVendor(req: Request): Promise<Response> {
  const host = mockHost(req);
  const url = new URL(req.url);
  const p = url.pathname;
  const q = url.searchParams;
  const h = (k: string) => req.headers.get(k);
  const body = req.method === "POST" ? await req.text() : "";
  const form = new URLSearchParams(body);

  if (host === "www.virustotal.com" && h("x-apikey") === "vt-key-123456") {
    if (p === "/api/v3/files/44d88612fea8a8f36de82e1278abb02f") {
      return json(vtAttrs({ type_description: "Win32 EXE", size: 68, names: ["a.exe", "b.exe", "c.exe", "d.exe", "e.exe", "f.exe"] }));
    }
    if (p === "/api/v3/domains/evil.example") return json(vtAttrs({ registrar: "Mock Registrar", creation_date: 1_600_000_000, whois: "w".repeat(700) }));
    if (p === "/api/v3/ip_addresses/198.51.100.7") return json(vtAttrs({ country: "NL", as_owner: "Mock AS", network: "198.51.100.0/24" }));
    if (p === `/api/v3/urls/${vtUrlId}`) return json(vtAttrs({ tags: [] }));
    return json({ error: { code: "NotFoundError" } }, 404);
  }
  if (host === "api.abuseipdb.com" && p === "/api/v2/check" && h("key") === "abuse-key-123456") {
    return json({
      data: {
        ipAddress: q.get("ipAddress"), abuseConfidenceScore: 87, totalReports: 14, countryCode: "NL", isp: "Mock ISP",
        domain: "mock.example", usageType: "Data Center/Web Hosting/Transit", isTor: true, isWhitelisted: false,
        lastReportedAt: "2026-10-09T12:00:00+00:00",
      },
    });
  }
  if (host === "api.shodan.io" && q.get("key") === "shodan-key-123456") {
    if (p === "/dns/resolve") {
      const n = q.get("hostnames") ?? "";
      return json({ [n]: n === "evil.example" ? "198.51.100.9" : null });
    }
    if (p === "/shodan/host/198.51.100.7" || p === "/shodan/host/198.51.100.9") {
      return json({
        ip_str: p.slice(13), hostnames: ["evil.example"], country_code: "NL", city: "Amsterdam", org: "Mock Org", isp: "Mock ISP",
        os: null, ports: [22, 80, 443, 3389], vulns: ["CVE-2024-0001", "CVE-2024-0002"], tags: ["cloud"], last_update: "2026-10-09T00:00:00.000000",
      });
    }
    return json({ error: "No information available for that IP." }, 404);
  }
  if (host === "api.greynoise.io" && h("key") === "gn-key-123456") {
    if (p === "/v3/community/198.51.100.7") {
      return json({
        ip: "198.51.100.7", noise: true, riot: false, classification: "malicious", name: "unknown",
        link: "https://viz.greynoise.io/ip/198.51.100.7", last_seen: "2026-10-09", message: "Success",
      });
    }
    return json({ message: "IP not observed scanning the internet or contained in RIOT data set." }, 404);
  }
  if (host === "otx.alienvault.com" && p === "/api/v1/indicators/domain/evil.example/general" && h("x-otx-api-key") === "otx-key-123456") {
    const pulses = Array.from({ length: 7 }, (_, i) => ({ name: `pulse ${i}`, created: "2026-10-01T00:00:00", tags: ["c2"], id: i }));
    return json({ pulse_info: { count: 7, pulses }, reputation: 0, country_code: null });
  }
  if (host === "urlhaus-api.abuse.ch") {
    if (p === "/v1/url/" && form.get("url") === "http://evil.example/x") {
      return json({
        query_status: "ok", threat: "malware_download", url_status: "online", tags: ["elf", "mirai"],
        blacklists: { spamhaus_dbl: "abused_legit_malware", surbl: "not listed" }, date_added: "2026-10-01 00:00:00 UTC", host: "evil.example",
      });
    }
    if (p === "/v1/host/" && form.get("host") === "evil.example") {
      return json({ query_status: "ok", url_count: 3, urls_online: 1, blacklists: { spamhaus_dbl: "not listed" }, host: "evil.example" });
    }
    return json({ query_status: "no_results" });
  }
  if (host === "mb-api.abuse.ch" && p === "/api/v1/" && form.get("query") === "get_info") {
    if (form.get("hash") === "44d88612fea8a8f36de82e1278abb02f") {
      return json({
        query_status: "ok",
        data: [{
          sha256_hash: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", sha1_hash: "3395856ce81f2b7382dee72602f798b642f14140",
          md5_hash: "44d88612fea8a8f36de82e1278abb02f", file_type: "exe", file_type_mime: "application/x-dosexec", file_size: 68,
          signature: "Emotet", reporter: "mock", first_seen: "2026-10-01 00:00:00", last_seen: null, delivery_method: "email_attachment",
          tags: ["exe", "emotet"], intelligence: { clamav: ["Win.Test.EICAR_HDB-1"], downloads: "10" },
        }],
      });
    }
    return json({ query_status: "hash_not_found" });
  }
  if (host === "threatfox-api.abuse.ch" && p === "/api/v1/") {
    const b = JSON.parse(body || "{}");
    if (b.query !== "get_iocs") return json({ query_status: "unknown_query" });
    const days = Number(b.days ?? 0);
    return json({
      query_status: "ok",
      data: [
        { ioc: "198.51.100.20:443", ioc_type: "ip:port", threat_type: "botnet_cc", malware: "win.cobalt_strike", confidence_level: 100, reporter: "mock", reference: null, first_seen_utc: "2026-10-09 00:00:00", last_seen_utc: null, tags: ["cs"] },
        { ioc: "[2001:db8::7]:8443", ioc_type: "ip:port", threat_type: "botnet_cc", malware: "elf.mirai", confidence_level: 60, reporter: "mock", reference: "https://example.org/r", first_seen_utc: "2026-10-09 00:00:00", last_seen_utc: null, tags: null },
        { ioc: `days${days}.evil.example`, ioc_type: "domain", threat_type: "payload_delivery", malware: "js.socgholish", confidence_level: 40, reporter: "mock", reference: null, first_seen_utc: "2026-10-09 00:00:00", last_seen_utc: null, tags: ["fakeupdate"] },
        { ioc: "", ioc_type: "domain", threat_type: "x", malware: "y", confidence_level: 10 },
        { ioc_type: "url", threat_type: "x" },
      ],
    });
  }
  if (host === "check.torproject.org" && p === "/torbulkexitlist") {
    return new Response("# exit list\n198.51.100.30\n198.51.100.31\n\n  198.51.100.32  \n", { headers: { "content-type": "text/plain" } });
  }
  return json({ error: "mock: bad auth or unknown route" }, 401);
}
