// NAN-3490 shadow runs: every enrichment's code.ts vs the connector.yaml next
// to it, against the same mock (vendors.ts). See README.md, "Shadow runs".
//
//   NANO_CONNECTOR_BIN=… deno test --cached-only --allow-read --allow-write \
//     --allow-net=127.0.0.1 --allow-run --allow-env testing/shadow/shadow.test.ts
//
// Agent enrichments: the result object is identical, including the
// not-found paths. Data enrichments: the records are identical (fetched_at
// aside, a wall-clock stamp) and the watermark advances. Enrichment results
// go to enrichment tables, not the lake, so there is no metadata.uid check.

import { assert, assertEquals } from "jsr:@std/assert@1";
import { parse } from "jsr:@std/yaml@1";
import { assertSame, diffEvents, type Json, runConnector, runDeno, serveMock, shadowIgnored } from "./lib.ts";
import { enrichmentVendor } from "./vendors.ts";

const root = new URL("../../enrichments/", import.meta.url);
const ignore = shadowIgnored();
const spec = (rel: string) => new URL(`${rel}/connector.yaml`, root).pathname;
const script = (rel: string) => new URL(`${rel}/code.ts`, root).href;

async function both(rel: string, deno: Record<string, unknown>, connector: Parameters<typeof runConnector>[2]) {
  const a = serveMock(enrichmentVendor);
  const b = serveMock(enrichmentVendor);
  try {
    const d = await runDeno(a, { script: script(rel), ...deno });
    const c = await runConnector(spec(rel), b, connector);
    return { d: d.result as Record<string, Json>, c: c.result as Record<string, Json> };
  } finally {
    await a.close();
    await b.close();
  }
}

const agentCases: [string, string, string, string][] = [
  ["virustotal", "44d88612fea8a8f36de82e1278abb02f", "hash", "vt-key-123456"],
  ["virustotal", "evil.example", "domain", "vt-key-123456"],
  ["virustotal", "198.51.100.7", "ip", "vt-key-123456"],
  ["virustotal", "http://evil.example/x?y=1", "url", "vt-key-123456"],
  ["virustotal", "00000000000000000000000000000000", "hash", "vt-key-123456"],
  ["abuseipdb", "198.51.100.7", "ip", "abuse-key-123456"],
  ["shodan", "198.51.100.7", "ip", "shodan-key-123456"],
  ["shodan", "evil.example", "domain", "shodan-key-123456"],
  ["shodan", "nothing.example", "domain", "shodan-key-123456"],
  ["greynoise", "198.51.100.7", "ip", "gn-key-123456"],
  ["greynoise", "198.51.100.8", "ip", "gn-key-123456"],
  ["otx", "evil.example", "domain", "otx-key-123456"],
  ["urlhaus", "http://evil.example/x", "url", "unused-123456"],
  ["urlhaus", "evil.example", "domain", "unused-123456"],
  ["urlhaus", "clean.example", "domain", "unused-123456"],
  ["malwarebazaar", "44d88612fea8a8f36de82e1278abb02f", "hash", "unused-123456"],
  ["malwarebazaar", "ffffffffffffffffffffffffffffffff", "hash", "unused-123456"],
];

for (const [name, artifact, type, key] of agentCases) {
  Deno.test({ name: `agent/${name} ${type} ${artifact}: Deno vs connector`, ignore }, async () => {
    const { d, c } = await both(
      `agent/${name}`,
      { kind: "agent", artifact, artifact_type: type, credentials: { API_KEY: key } },
      { creds: { API_KEY: key }, artifact: [artifact, type] },
    );
    assertSame(diffEvents(`agent/${name} ${type} ${artifact}`, [d], [c]));
  });
}

const dataCases: [string, string | null][] = [["threatfox", null], ["threatfox", "2026-10-09T00:00:00.000Z"], ["tor-exit-nodes", null]];

for (const [dir, wm] of dataCases) {
  Deno.test({ name: `data/${dir} (watermark ${wm}): Deno vs connector`, ignore }, async () => {
    const s = parse(await Deno.readTextFile(spec(`data/${dir}`))) as { streams: { id: string }[] };
    const { d, c } = await both(
      `data/${dir}`,
      { kind: "data", credentials: { API_KEY: "tf-key-123456" }, last_watermark: wm },
      { creds: { API_KEY: "tf-key-123456" }, checkpoints: wm ? { [s.streams[0].id]: { state: { watermark: wm } } } : undefined },
    );
    assert(typeof c.watermark === "string", "watermark advanced");
    const records = (c.records ?? []) as Json[];
    assert(records.length > 0);
    assertSame(diffEvents(`data/${dir} (watermark ${wm})`, (d.records ?? []) as Json[], records, ["fetched_at"]));
  });
}

// Runs without the connector binary: the manifest <-> spec contract.
Deno.test("every connector.yaml is declared by its manifest and only uses declared credentials", async () => {
  const problems: string[] = [];
  let n = 0;
  for (const kind of ["agent", "data"]) {
    for await (const e of Deno.readDir(new URL(`${kind}/`, root))) {
      if (!e.isDirectory) continue;
      const rel = `${kind}/${e.name}`;
      let text: string;
      try {
        text = await Deno.readTextFile(spec(rel));
      } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
          problems.push(`${rel}: no connector.yaml`);
          continue;
        }
        throw err;
      }
      n++;
      const m = parse(await Deno.readTextFile(new URL(`${rel}/manifest.yaml`, root))) as {
        runtime?: string;
        connector_spec?: string;
        credential_fields?: { name: string }[];
      };
      const s = parse(text) as { kind: string; auth?: Record<string, string> };
      if (m.connector_spec !== "connector.yaml") problems.push(`${rel}: manifest connector_spec is not connector.yaml`);
      if (m.runtime !== "deno" && m.runtime !== "connector") problems.push(`${rel}: manifest runtime must be deno or connector`);
      if (s.kind !== `${kind}_enrichment`) problems.push(`${rel}: spec kind ${s.kind}, expected ${kind}_enrichment`);
      const creds = new Set((m.credential_fields ?? []).map((f) => f.name));
      for (const [k, v] of Object.entries(s.auth ?? {})) {
        if ((k === "credential" || k.endsWith("_credential")) && !creds.has(v)) problems.push(`${rel}: auth uses credential ${v}, not in the manifest`);
      }
      if (/\.config\.|\{\{\s*config\./.test(text)) problems.push(`${rel}: enrichment specs take no config`);
    }
  }
  assertEquals(n, 9);
  assertEquals(problems, []);
});
