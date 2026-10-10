# nano enrichments

Official enrichment catalog for [nano](https://nano.rs). A small registry of
ready-to-use threat intelligence, geolocation, and IOC feeds that you can wire
into your nano deployment without writing any code.

## Using this catalog

In your nano UI, go to **Settings → Marketplace → Repositories** and add:

```
https://github.com/nano-rs/nano-enrichments
```

The marketplace catalog populates a few minutes later. From the catalog you can
install any enrichment with one click — supply credentials when prompted, and
that's it.

## What's in here

Enrichments come in two shapes:

| Type | When it runs | Use for |
|---|---|---|
| `agent` | On-demand, per artifact | Lookups against an external API. IP, domain, hash, or URL gets sent to the provider on first sighting, and the result is cached. Pay-per-call or rate-limited providers. |
| `data` | On a schedule | Bulk feeds. The whole dataset is fetched and stored locally; matches against ingested events are then a fast dict lookup. Free or low-cost feeds with reasonable size. |

Today the catalog ships:

**Agent (on-demand):** AbuseIPDB · GreyNoise · MalwareBazaar · OTX · Shodan · URLhaus · VirusTotal

**Data (bulk):** ThreatFox · Tor Exit Nodes

## Layout

```
enrichments/
  agent/<slug>/
    manifest.yaml
    connector.yaml
    code.ts
  data/<slug>/
    manifest.yaml
    connector.yaml
    code.ts
```

Each enrichment is a directory with three files:

- `manifest.yaml` — name, slug, category, credential requirements, schedule, allowed outbound domains, tags.
- `connector.yaml` — the declarative nano connector spec (NAN-3490) that
  replaces `code.ts`. The manifest's `runtime` (`deno` or `connector`) says
  which one runs, and `connector_spec` names the file. The spec format is
  documented in nanosiem's `nano-connector/docs/AUTHORING.md`.
- `code.ts` — the TypeScript that runs in nano's Deno sandbox, until the
  cutover to the connector engine.

Custom Deno enrichments written outside this repo have no conversion path;
they stop running at the cutover.

## Shadow runs

`testing/shadow/` proves each `connector.yaml` returns what its `code.ts`
returns. For every enrichment it runs the unmodified script (under a port of
nano's Deno auth wrapper) and `nano-connector shadow` against the same vendor
mock (`testing/shadow/vendors.ts`, synthetic data that checks each vendor's
auth) and compares the results:

- agent enrichments: the result object, including the not-found paths;
- data enrichments: the records (minus the wall-clock `fetched_at`), and that
  the watermark advances.

A contract test needs no binary and always runs: every enrichment has a
`connector.yaml` that its manifest names, with a `runtime`, the right `kind`,
and only credentials the manifest declares.

```sh
# contract only
deno test --allow-read --allow-env testing/shadow/shadow.test.ts
# full shadow run
NANO_CONNECTOR_BIN=/path/to/nano-connector \
  deno test --allow-read --allow-write --allow-net=127.0.0.1 --allow-run --allow-env \
  testing/shadow/shadow.test.ts
```

Without `NANO_CONNECTOR_BIN` the shadow tests are skipped, unless
`NANO_SHADOW_REQUIRED=1` (CI). `.github/workflows/shadow.yml` builds
`nano-connector` from nanosiem.

MalwareBazaar: the spec sends no key, like `code.ts`. abuse.ch now requires an
`Auth-Key` on its APIs, so both need a credential field in a follow-up.

## Writing your own

The two enrichment shapes have different entry points. Both export a single
`enrich` function and receive credentials at call time — never hard-code keys.

**Agent (on-demand lookup):**

```typescript
async function enrich(
  artifact: string,                // the value being looked up
  artifactType: string,            // "ip" | "domain" | "hash" | "url"
  credentials: Record<string, string>,
): Promise<AgentEnrichmentResult> {
  // Call the provider, return { risk_score, tags, data }
}
export { enrich };
```

**Data (bulk feed):**

```typescript
async function enrich(context: {
  lastWatermark?: string;           // set on incremental syncs
  credentials: Record<string, string>;
}): Promise<DataEnrichmentResult> {
  // Fetch the feed, return { records: [...], watermark }
}
export { enrich };
```

Full reference (manifest fields, allowed outbound domains, sandbox limits,
credential rotation) is in the [nano docs](https://nano.rs/docs/).

## Contributing

Pull requests welcome. Bump the manifest `version` whenever you change `code.ts`
or the manifest schema, and add a one-line `changelog:` describing what
changed — installed enrichments use that to surface "an update is available"
in the UI.

## License

MIT
