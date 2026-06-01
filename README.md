# reds_client.py

A command-line client for the **RationalEdge DataSet (REDS) API v1** — query the
RationalEdge malware dataset: look up samples by hash, run field-based searches
with the REDS query operators, browse strings, IOCs and decompiled code, and
manage analysis jobs.

- Base API: `https://reds.rationaledge.io/api/v1`
- Single file, **no dependencies** — Python 3.7+ standard library only.
- API token is stored securely in the **macOS Keychain**.

## Getting access

REDS is currently invite/demo-based. To request **demo access** and an API
token, visit <https://rationaledge.io> and apply through the site, or email the
team at <reds@rationaledge.io> with a short note about your use case (e.g. IR
triage or threat-actor tracking). You will need an API token before any of the
commands below will work — see [Authentication](#authentication).

## Requirements

- Python 3.7 or newer.
- macOS for `--set-api-key` (uses the `security` keychain tool). On other
  platforms, supply the token via `--api-key` or the `REDS_API_TOKEN`
  environment variable instead.
- A REDS API token (from your RationalEdge account).

## Installation

```sh
chmod +x reds_client.py
./reds_client.py --help
```

## Authentication

The client resolves the API token in this order:

1. `--api-key TOKEN` command-line flag
2. `REDS_API_TOKEN` environment variable
3. macOS Keychain (service `reds-api`)

Store a token in the Keychain (prompts securely, no echo):

```sh
./reds_client.py --set-api-key
```

Remove it:

```sh
./reds_client.py --delete-api-key
```

## Global options

| Option | Description |
|---|---|
| `--usage` | Show current quota usage and limits and exit (alias for `quota`). |
| `--set-api-key` | Store an API token in the macOS Keychain and exit. |
| `--delete-api-key` | Remove the stored API token from the Keychain and exit. |
| `--api-key TOKEN` | Use this token (overrides env var and Keychain). |
| `-o`, `--output FILE` | Write the result to `FILE` instead of stdout (for `download`, the saved ZIP path). |
| `--json` | Emit raw JSON output (default is a human-readable rendering). |
| `--debug` | Verbose request/response logging to stderr. |
| `--timeout SEC` | HTTP request timeout in seconds (default 60). |
| `--version` | Print the client version and exit. |

Global options work both before and after the subcommand:

```sh
./reds_client.py --json search 'filetype_magika="pebin"'
./reds_client.py search 'filetype_magika="pebin"' --json
```

## Commands

### Search

| Command | Description |
|---|---|
| `search QUERY` | Search across all collections with the query language. |
| `code-search QUERY` | Search decompiled / disassembled functions. |
| `strings-search QUERY` | Browse strings across the dataset. |
| `strings-samples STRING` | List samples containing an exact string (raw value, no quotes). |
| `bulk-search --field F --values ...` | Search up to 300 exact values of one field. |
| `bulk-fields` | List fields available for bulk-search. |

`search`, `code-search` and `strings-search` accept `--cursor` for pagination
and `--all` to follow cursors and merge every page (`--max-pages` caps it,
default 50). `search` also accepts `--fields` (comma-separated) and
`--format json|ndjson`.

### Sample lookup

| Command | Description |
|---|---|
| `file HASH` | Full sample details by MD5, SHA1 or SHA256 hash. |
| `download HASH` | Download a sample as a password-protected ZIP (`-o`/`--output`, `--extract`, `--extract-dir`). |

### Per-sample analysis

| Command | Description |
|---|---|
| `validate SHA256` | Check code-analysis data availability. |
| `code-stats SHA256` | Code-analysis statistics. |
| `functions SHA256` | Decompiled/disassembled functions (`--kind decompiled\|disassembled`). |
| `string-stats SHA256` | String statistics for a sample. |
| `sample-strings SHA256` | Strings extracted from a sample (filters: `--search`, `--encoding`, `--min-entropy`, `--max-entropy`). |
| `iocs SHA256` | IOCs extracted from a sample (`--summary`, `--types`, `--no-counts`). |

`functions` and `sample-strings` support `--cursor`, `--limit` and `--all`.

### Metadata & jobs

| Command | Description |
|---|---|
| `collections` | List available collections. |
| `fields [--collection C]` | List searchable fields. |
| `stats` | Dataset statistics. |
| `quota` | Current quota usage and upload limits. |
| `upload FILE` | Upload a local sample (≤100MB) for analysis (`--private`); returns a `job_id`. |
| `analyze SHA256` | Queue analysis for a catalog-only sample. |
| `analyze-code SHA256` | Queue code analysis for an already-analysed sample. |
| `job JOB_ID` | Status of an analysis job. |
| `jobs` | List your analysis jobs (`--status`, `--limit`, `--offset`). |
| `queue` | Analysis queue status. |
| `operators` | Print the query operator and schema field reference (offline). |

## Search query operators

| Operator | Syntax | Meaning | Example |
|---|---|---|---|
| Partial match | `field:"value"` | Case-insensitive whole-word match | `filetype_magika:"pebin"` |
| Exact match | `field="value"` | Exact value match | `packer="UPX"` |
| Numeric `>` | `field:>N` | Greater than | `filesize:>100000` |
| Numeric `<` | `field:<N` | Less than | `filesize:<1000` |
| AND | `+` | Term must be included | `filetype:"PE32" +filesize:>1000` |
| OR | `\|` | Either term matches | `filetype:"PE32" \|filetype:"ELF"` |
| NOT | `-` | Term must be excluded | `-is_packed=1` |

Notes:

- **AND (`+`) and OR (`\|`) cannot be mixed** in one query — the API rejects it
  with HTTP 400. The client detects this client-side (ignoring operators inside
  quoted values) and aborts early with a clear message.
- `string:"x"` (partial) returns string metadata; `string="x"` (exact) returns
  sample hashes.
- Regex search (`::`) is web-UI only and not available in API v1.

Run `./reds_client.py operators` for the full operator reference plus a summary
of searchable field families (Common, DIE, IOCs, PE, ELF, Mach-O, APK, JS, Code).

## Examples

```sh
# Store the API token once
./reds_client.py --set-api-key

# Look up a sample by hash (MD5, SHA1 or SHA256)
./reds_client.py file 0f5409a5df1f916fe532696746a46d92cb561d981953d9ec30712d6d4670a13f

# Field search with operators, JSON output
./reds_client.py --json search 'filetype_magika="pebin" +filesize:>100000'

# OR query, follow all pages
./reds_client.py search 'packer="UPX" |packer="KByS"' --all

# IOC search and exact string search
./reds_client.py search 'cve="CVE-2021-44228"'
./reds_client.py search 'string="GetProcAddress"'

# Per-sample drill-down
./reds_client.py iocs 0f5409a5df1f916fe532696746a46d92cb561d981953d9ec30712d6d4670a13f --summary
./reds_client.py functions 0f5409a5...0a13f --kind disassembled --all
./reds_client.py sample-strings 0f5409a5...0a13f --min-entropy 4.5

# Bulk-check hashes from a threat report
./reds_client.py bulk-search --field sha256 --values-file hashes.txt

# Decompiled code search
./reds_client.py code-search 'decompiled_function:"CreateFile"'

# SOC triage enrichment — risk level, behaviours, and IOCs for an alerted sample
./reds_client.py file 0f5409a5df1f916fe532696746a46d92cb561d981953d9ec30712d6d4670a13f
./reds_client.py iocs 0f5409a5...0a13f --summary

# Attribution clues — pivot on build artefacts and toolchain fingerprints
./reds_client.py search 'dbg_pdb_info:"builder"'
./reds_client.py search 'certificate_thumbprint="B69E752BBE88B4458200A7C0F4F5B3CCE6F35B47"'

# Cryptocurrency tracking — samples referencing a wallet address
./reds_client.py search 'crypto_btc="1d74b0778ed2581c9b4779447ec1f929"'
./reds_client.py search 'crypto_eth="0x71C7656EC7ab88b098defB751B7401B5f6d8976F"'

# Download and extract a sample (ZIP password: infected)
./reds_client.py download 0f5409a5...0a13f --extract

# Save a sample to a specific path
./reds_client.py download 0f5409a5...0a13f -o /samples/suspect.zip

# Upload a local sample for analysis, then poll the returned job
./reds_client.py upload /samples/suspect.bin
./reds_client.py upload /samples/suspect.bin --private   # premium: org-only
./reds_client.py job job_2184fe9c-b40e-481d-b24a-28cd46e3625e

# Account info / quota
./reds_client.py quota
./reds_client.py --usage            # same thing, top-level shortcut

# Save command output to a file instead of stdout
./reds_client.py --json search 'filetype_magika="pebin"' -o results.json
```

## Output

- Default: a human-readable rendering — search results are summarised with a
  per-result key/value listing; long values are truncated.
- `--json`: raw JSON (`indent=2`), suitable for piping into `jq`.
- `-o`/`--output FILE`: write that rendering (human or `--json`) to `FILE`
  instead of stdout; a short confirmation is printed to stderr.

```sh
./reds_client.py --json search 'filetype_magika="pebin"' | jq '.results[]._source.sha256'
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | No subcommand given / key-management failure |
| `2` | Client-side error (bad input, network error, generic API error) |
| `3` | Unauthorized / forbidden (HTTP 401 / 403) |
| `4` | Not found (HTTP 404) |
| `5` | Rate limited / quota exceeded (HTTP 429) |
| `130` | Interrupted (Ctrl-C) |

In `--json` mode, errors are also printed to stderr as a JSON envelope
(`{"error": true, "status": ..., "code": ..., "message": ...}`).

## Notes

- The API host is behind Cloudflare bot protection that blocks the default
  `Python-urllib` User-Agent, so the client sends a descriptive `User-Agent`
  header. A `403 ... browser's signature` response indicates an upstream
  network block rather than an authentication problem.
- Quotas are per day and per month — check usage with the `quota` command.
- Downloaded sample ZIPs are password-protected; the password is `infected`.
- `upload` sends one file (≤100MB) per call and counts against the **upload**
  quota shown by `quota`. `--private` requires a premium subscription (else
  HTTP 403). The response includes a `sha256`, a `job_id` to poll with `job`,
  and `duplicate_detected` if REDS already had that sample.

## Contributing

Bug reports and patches are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

- **Reporting issues** — open an issue on the project's issue tracker, or email
  <reds@rationaledge.io>. Include the command you ran, the output from re-running
  it with `--debug`, your OS, and `python3 --version`. Do not paste an API token
  (the client only shows the first/last few characters of it in `--debug` output,
  but double-check before sharing).
- **No third-party dependencies** — the client is intentionally single-file and
  standard-library only; please keep it that way.
- **Running the tests** — the suite is standard-library only:

  ```sh
  python3 -m unittest discover -s tests -v
  ```

## License

Released under the [MIT License](LICENSE).

## Potential Use cases

REDS combines code-level analysis, fuzzy hashing, source-traced IOC extraction,
and behaviour mapping across PE/ELF/Mach-O/APK/JS. Workflows it supports:

- **SOC triage enrichment** — given an alerted hash, return risk level, MITRE
  ATT&CK techniques, and a vetted IOC set to auto-prioritise and sweep
  (`file`, `iocs --summary`).
- **IOC validation & hunting** — bulk-check report indicators; `bulk_search_meta`
  flags what is net-new (`bulk-search`).
- **Campaign pivoting** — fan out from one C2 indicator to every sample sharing
  it (`search 'ipv4="..."'`).
- **Family & variant discovery** — cluster variants with disassembly ssdeep/TLSH
  and shared rare functions (`code-search`).
- **Attribution clues** — pivot on PDB paths, build IDs, compiler/linker
  fingerprints, and reused code-signing certificates.
- **Cryptocurrency tracking** — find samples referencing a wallet address across
  ransomware and clippers (`search 'crypto_btc="..."'`).
- **Detection engineering** — mine rare strings and CAPA techniques for
  high-fidelity YARA/SIEM rules, and test rule coverage (`rule_name:"..."`).
- **Code-signing abuse research** — hunt stolen/abused certificates and
  attestation-signed malware.
- **Tampering forensics** — Rich Header inconsistency tests, plus APK zip-bomb
  and hidden-DEX checks.
- **Mobile malware analysis** — droppers (`contains_embedded_apk=1`), permission
  abuse, and obfuscation indicators.
- **Malicious JavaScript triage** — obfuscation metrics and deobfuscation deltas.
- **Pipeline / SOAR integration** — on-demand analysis plus job polling wired
  into automated ingestion.
- **ML / research corpus** — a labelled, feature-rich dataset for similarity
  models and classifiers.

## REDS vs. VirusTotal

REDS is not a replacement for VirusTotal — it is the code-level layer VT lacks.
VirusTotal excels at **breadth and verdicts**: 70+ AV engine results, a huge
crowdsourced corpus, sandbox/dynamic behaviour reports, passive DNS/whois, the
VT Graph, and VT Intelligence content/livehunt search. It answers *"is this
known-bad, and what does the ecosystem already know about it?"*

What VT does not expose well is the decompiled/disassembled code itself,
function-level similarity across the corpus, or normalized-code matching — its
similarity is largely file-level (imphash, ssdeep, vhash). REDS occupies that
gap. It indexes **decompiled and disassembled code** (plus three normalized
disassembly variants) and makes it full-text- and regex-searchable across the
whole dataset, with **function- and string-level rarity classification**
(unique → rare → uncommon → common → library) that separates campaign-specific
tradecraft from compiler boilerplate. It also extracts **IOCs traced back to the
exact function or string offset** that produced them, applies CAPA (MITRE
ATT&CK/MBC) and Chainguard Malcontent behaviour mappings with a maliciousness
risk score, and supports private uploads and on-demand analysis.

| Need | VirusTotal | REDS |
|---|---|---|
| Multi-engine verdict / reputation | Strong (70+ engines) | Risk score + YARA/behaviour, no AV aggregation |
| Corpus size / recall | Very large | Smaller, focused dataset |
| Decompiled/disassembled code search | Not exposed | Full-text + RE2 regex, dataset-wide |
| Cross-sample similarity | File-level (imphash, ssdeep, vhash) | Function-level + normalized-code ssdeep/TLSH |
| Rarity signal | None | 5-tier rarity on functions and strings |
| IOC context | Listed | Traced to source function/string offset |
| Infrastructure (passive DNS, whois) | Strong | Not offered |
| Proactive hunting (livehunt/retrohunt) | In production | On roadmap, not yet shipped |
| Private analysis (no public submission) | Limited | Private uploads + on-demand analysis |

> **Roadmap caveat:** YARA livehunt, retrohunt, and saved-query alerts are on the
> REDS roadmap (short-term) but **not yet shipped**. Until then, proactive
> catching of new samples means re-running queries or polling via the API.

### Use case: IR triage

In an active incident, triage means answering four questions fast: *is this
malicious, what does it do, how bad is the blast radius, and what do I sweep the
estate for?* Uploading an unknown sample to public VirusTotal is an OPSEC event —
many adversaries monitor VT for their own hashes, and a first-submission
timestamp warns them their implant was found. REDS closes that gap:

- **Private upload + on-demand analysis** — analyse a freshly pulled sample for
  your org only, without tipping the adversary, and get back a maliciousness
  risk score, CAPA/ATT&CK and Malcontent behaviour mappings, YARA hits, and an
  AI-generated full-sample summary a first responder can read in seconds.
- **Source-traced IOC extraction** — every C2 address, domain, URL, and file
  path is pulled from code and strings and tied to the function/offset it came
  from, giving a vetted indicator set to push straight into EDR/firewall/SIEM
  sweeps (`reds_client.py iocs SHA256`).
- **Bulk search** — test every hash, IP, and domain already in your incident
  logs against the dataset in one call, so you immediately see what is known and
  what is net-new (`reds_client.py bulk-search`).
- **Code-level capability confirmation** — function/string search confirms
  whether the sample really encrypts, exfiltrates, or persists, rather than
  inferring it from an engine label.
- **`first_seen`/`last_seen`** — direct inputs to dwell-time and scoping
  estimates.

All endpoints are scriptable via this client, so triage enrichment drops into a
SOAR playbook the instant a sample lands. Division of labour: VirusTotal for
fast ecosystem reputation on already-public hashes; REDS as the private,
code-grounded layer that confirms capability and hands you the containment
indicator list — without telling the attacker you are onto them.

### Use case: threat-actor tracking

Threat-actor tracking is the long game: maintaining attributed clusters, linking
campaigns over months, and recognising a known adversary's tooling when it
resurfaces. Here VT Intelligence is a genuine competitor (retrohunt, livehunt,
content search, VT Graph) and is stronger on **infrastructure** attribution
(passive DNS, whois, submitter metadata) and on raw recall. REDS' edge is
**code DNA** — the evidence attribution actually rests on:

- **Function-level correlation with rarity** — shared *rare/unique* functions
  across otherwise unrelated samples are a strong authorship signal; library/
  boilerplate code is filtered out automatically.
- **Normalized-code ssdeep/TLSH** — links survive recompilation, compiler-flag
  changes, and minor mutation, so you track an actor's evolving codebase rather
  than a frozen artefact.
- **Full-text/regex code search** — hunt an actor's signature routines: custom
  crypto, mutex/pipe names, PDB paths, builder artefacts, unique error strings.
- **Toolchain fingerprints** — richhash/richpe (Rich Header), authentihash,
  import/export/section hashes, and searchable code-signing certificate fields
  (thumbprint, issuer, serial) catch reused dev environments and abused certs.
- **CAPA/ATT&CK + Malcontent** — confirm TTP consistency across a cluster;
  **`first_seen`/`last_seen`** build the campaign timeline.

Realistic division of labour today: VirusTotal Intelligence for breadth,
infrastructure pivoting, and — until REDS ships livehunt/retrohunt — proactive
hunting of new actor samples; REDS as the code-DNA layer that proves common
authorship, tracks a toolkit across versions, and supplies the structural
evidence an attribution assessment is written on. Reassess once the REDS
roadmap livehunt, retrohunt, and saved-query alerts ship.
