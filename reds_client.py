#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 RationalEdge
"""
reds_client.py - Command line client for the RationalEdge DataSet (REDS) API v1.

Query the RationalEdge malware dataset: look up samples by hash, run field-based
searches with the REDS query operators, browse strings/IOCs/decompiled code, and
more.

The API token is stored in the macOS Keychain (service "reds-api"). Resolution
order for the token: --api-key flag, then $REDS_API_TOKEN, then the Keychain.

Reference: REDS_api.pdf (API spec) and REDS_dataSchema.pdf (searchable fields).
"""

import argparse
import contextlib
import io
import json
import logging
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

__version__ = "1.0.0"

BASE_URL = "https://reds.rationaledge.io/api/v1"
KEYCHAIN_SERVICE = "reds-api"
KEYCHAIN_ACCOUNT = "api-token"
ZIP_PASSWORD = b"infected"
ENV_VAR = "REDS_API_TOKEN"
# A descriptive User-Agent; the default urllib agent is bot-blocked upstream.
USER_AGENT = f"reds-client/{__version__} (+https://reds.rationaledge.io)"

log = logging.getLogger("reds")

# Hex length -> hash algorithm name.
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------
class REDSError(Exception):
    """Client-side error (bad input, missing token, keychain failure)."""


class REDSAPIError(REDSError):
    """Error returned by the REDS API."""

    def __init__(self, status, code, message, detail=None):
        self.status = status
        self.code = code
        self.message = message
        self.detail = detail
        super().__init__(f"[HTTP {status}] {code}: {message}")


# --------------------------------------------------------------------------
# Keychain helpers (macOS `security` command)
# --------------------------------------------------------------------------
def keychain_set_token(token):
    """Store/update the API token in the login keychain."""
    try:
        subprocess.run(
            ["security", "add-generic-password", "-U",
             "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w", token],
            check=True, capture_output=True, text=True)
    except FileNotFoundError:
        raise REDSError("`security` command not found - the Keychain is only "
                        "available on macOS.")
    except subprocess.CalledProcessError as exc:
        raise REDSError(f"Failed to store API key in Keychain: "
                        f"{exc.stderr.strip()}")


def keychain_get_token():
    """Return the stored API token, or None if not present."""
    try:
        result = subprocess.run(
            ["security", "find-generic-password",
             "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"],
            capture_output=True, text=True)
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def keychain_delete_token():
    """Remove the stored API token. Returns True if something was deleted."""
    try:
        result = subprocess.run(
            ["security", "delete-generic-password",
             "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT],
            capture_output=True, text=True)
    except FileNotFoundError:
        raise REDSError("`security` command not found - the Keychain is only "
                        "available on macOS.")
    return result.returncode == 0


def resolve_token(cli_token):
    """Resolve the API token: CLI flag > env var > Keychain."""
    if cli_token:
        log.debug("using API token from --api-key")
        return cli_token
    env_token = os.environ.get(ENV_VAR)
    if env_token:
        log.debug("using API token from $%s", ENV_VAR)
        return env_token
    kc_token = keychain_get_token()
    if kc_token:
        log.debug("using API token from Keychain")
        return kc_token
    raise REDSError(
        "No API token found. Save one with `reds_client.py --set-api-key`, "
        f"set ${ENV_VAR}, or pass --api-key.")


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------
def validate_hash(value, sha256_only=False):
    """Validate an MD5/SHA1/SHA256 hash and return it lower-cased."""
    h = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", h) or len(h) not in HASH_LENGTHS:
        raise REDSError(
            f"Invalid hash '{value}': expected 32 (MD5), 40 (SHA1) or "
            f"64 (SHA256) hexadecimal characters.")
    if sha256_only and len(h) != 64:
        raise REDSError(
            "This endpoint requires a full SHA256 hash (64 hex characters).")
    return h


def check_query(query):
    """Warn/abort on a query that mixes AND (+) and OR (|) operators.

    The REDS API rejects mixed operators with HTTP 400, so catch it early.
    Quoted values are stripped first so operators inside a value are ignored.
    """
    if not query or not query.strip():
        raise REDSError("Empty search query.")
    outside_quotes = re.sub(r'"[^"]*"', "", query)
    has_and = "+" in outside_quotes
    has_or = "|" in outside_quotes
    if has_and and has_or:
        raise REDSError(
            "Query mixes AND (+) and OR (|) operators. The REDS API does not "
            "support mixed operators and would reject this with HTTP 400. "
            "Use only one operator type per query.")


# --------------------------------------------------------------------------
# multipart/form-data encoding (stdlib only, for file uploads)
# --------------------------------------------------------------------------
def _encode_multipart(file_field, filename, file_bytes, extra_fields=None):
    """Build a multipart/form-data body.

    Returns (content_type, body_bytes). The file part is written last so its
    raw bytes are never run through any text transform.
    """
    boundary = "----redsclient" + uuid.uuid4().hex
    bnd = boundary.encode("ascii")
    crlf = b"\r\n"
    # Header values cannot contain quotes or newlines; strip them defensively.
    safe_name = filename.replace('"', "").replace("\r", "").replace("\n", "")
    out = bytearray()
    for name, value in (extra_fields or {}).items():
        out += b"--" + bnd + crlf
        out += ('Content-Disposition: form-data; name="%s"' % name) \
            .encode("utf-8") + crlf + crlf
        out += str(value).encode("utf-8") + crlf
    out += b"--" + bnd + crlf
    out += ('Content-Disposition: form-data; name="%s"; filename="%s"'
            % (file_field, safe_name)).encode("utf-8") + crlf
    out += b"Content-Type: application/octet-stream" + crlf + crlf
    out += file_bytes + crlf
    out += b"--" + bnd + b"--" + crlf
    return "multipart/form-data; boundary=" + boundary, bytes(out)


# --------------------------------------------------------------------------
# HTTP client
# --------------------------------------------------------------------------
class REDSClient:
    """Thin wrapper over the REDS API v1 endpoints."""

    def __init__(self, token, timeout=60):
        self.token = token
        self.timeout = timeout

    # -- core request -------------------------------------------------------
    def _request(self, method, path, params=None, json_body=None, raw=False,
                 body=None, content_type=None):
        url = BASE_URL + path
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url += "?" + urllib.parse.urlencode(clean)

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        data = None
        if body is not None:
            data = body
            if content_type:
                headers["Content-Type"] = content_type
        elif json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        log.debug("--> %s %s", method, url)
        log.debug("    headers: Authorization: Bearer %s...%s",
                  self.token[:4], self.token[-4:] if len(self.token) > 8 else "")
        if json_body is not None:
            log.debug("    body: %s", json.dumps(json_body))
        elif body is not None:
            log.debug("    body: %d bytes (%s)", len(body),
                      content_type or "application/octet-stream")

        req = urllib.request.Request(url, data=data, method=method,
                                     headers=headers)
        started = time.time()
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            body = resp.read()
            status = resp.getcode()
        except urllib.error.HTTPError as exc:
            body = exc.read()
            status = exc.code
        except urllib.error.URLError as exc:
            raise REDSError(f"Network error contacting REDS API: {exc.reason}")
        elapsed_ms = (time.time() - started) * 1000.0
        log.debug("<-- HTTP %s  (%.1f ms, %d bytes)",
                  status, elapsed_ms, len(body))

        ok = 200 <= status < 300
        if raw and ok:
            return body

        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            if ok:
                return body
            raise REDSAPIError(status, f"http_{status}",
                               body[:300].decode("utf-8", "replace"))

        if not ok:
            raise self._build_error(status, payload)
        return payload

    @staticmethod
    def _build_error(status, payload):
        """Normalise the several error envelope shapes REDS returns."""
        if isinstance(payload, dict):
            code = (payload.get("code") or payload.get("error_code")
                    or f"http_{status}")
            message = (payload.get("message") or payload.get("detail")
                       or payload.get("error") or "Request failed")
            detail = payload.get("detail") if payload.get("message") else \
                payload.get("details")
        else:
            code, message, detail = f"http_{status}", str(payload), None
        return REDSAPIError(status, code, message, detail)

    # -- search endpoints ---------------------------------------------------
    def search(self, query, cursor=None, fields=None, fmt=None):
        return self._request("GET", "/search", params={
            "q": query, "cursor": cursor, "fields": fields, "format": fmt})

    def code_search(self, query, cursor=None):
        return self._request("GET", "/code/search",
                              params={"q": query, "cursor": cursor})

    def strings_search(self, query, cursor=None):
        return self._request("GET", "/strings/search",
                              params={"q": query, "cursor": cursor})

    def strings_samples(self, string_value, offset=0, limit=20):
        return self._request("GET", "/strings/samples", params={
            "string": string_value, "offset": offset, "limit": limit})

    def bulk_search(self, field, values, cursor=None):
        body = {"field": field, "values": values}
        if cursor:
            body["cursor"] = cursor
        return self._request("POST", "/bulk-search", json_body=body)

    def bulk_search_fields(self):
        return self._request("GET", "/bulk-search/fields")

    # -- sample lookup ------------------------------------------------------
    def file(self, hash_value):
        return self._request("GET", f"/file/{hash_value}")

    def download(self, hash_value):
        return self._request("GET", f"/download/{hash_value}", raw=True)

    # -- metadata -----------------------------------------------------------
    def collections(self):
        return self._request("GET", "/collections")

    def fields(self, collection=None):
        return self._request("GET", "/fields",
                              params={"collection": collection})

    def stats(self):
        return self._request("GET", "/stats")

    def quota(self):
        return self._request("GET", "/quota")

    # -- per-sample analysis ------------------------------------------------
    def validation(self, sha256):
        return self._request("GET", f"/samples/{sha256}/validation")

    def code_statistics(self, sha256):
        return self._request("GET", f"/samples/{sha256}/code-statistics")

    def functions(self, sha256, kind, cursor=None, limit=50):
        return self._request("GET", f"/samples/{sha256}/functions/{kind}",
                              params={"cursor": cursor, "limit": limit})

    def string_statistics(self, sha256):
        return self._request("GET", f"/samples/{sha256}/strings/statistics")

    def sample_strings(self, sha256, cursor=None, limit=500, search=None,
                       encoding=None, min_entropy=None, max_entropy=None):
        return self._request("GET", f"/samples/{sha256}/strings", params={
            "cursor": cursor, "limit": limit, "search": search,
            "encoding": encoding, "min_entropy": min_entropy,
            "max_entropy": max_entropy})

    def iocs(self, sha256, include_counts=True, ioc_types=None):
        params = {"include_counts": str(include_counts).lower()}
        if ioc_types:
            params["ioc_types"] = ioc_types
        return self._request("GET", f"/samples/{sha256}/iocs", params=params)

    def iocs_summary(self, sha256):
        return self._request("GET", f"/samples/{sha256}/iocs/summary")

    # -- upload -------------------------------------------------------------
    def upload(self, file_bytes, filename, private=False):
        extra = {"private": "true"} if private else None
        content_type, body = _encode_multipart(
            "file", filename, file_bytes, extra_fields=extra)
        return self._request("POST", "/upload", body=body,
                             content_type=content_type)

    # -- analysis jobs ------------------------------------------------------
    def analyze_sample(self, sha256):
        return self._request("POST", f"/analyze-sample/{sha256}")

    def analyze_code(self, sha256):
        return self._request("POST", f"/analyze-code/{sha256}")

    def job(self, job_id):
        return self._request("GET", f"/job/{job_id}")

    def jobs(self, status=None, limit=50, offset=0):
        return self._request("GET", "/jobs", params={
            "status": status, "limit": limit, "offset": offset})

    def queue_status(self):
        return self._request("GET", "/queue/status")


# --------------------------------------------------------------------------
# Cursor pagination
# --------------------------------------------------------------------------
def paginate(fetch, max_pages=50):
    """Follow `next_cursor` from a search-style endpoint and merge results.

    `fetch` is a callable taking a single `cursor` argument.
    """
    cursor = None
    merged = None
    pages = 0
    while pages < max_pages:
        page = fetch(cursor)
        pages += 1
        if merged is None:
            merged = page
        else:
            for key in ("results", "data"):
                if isinstance(page.get(key), list):
                    merged.setdefault(key, []).extend(page[key])
        has_more = page.get("has_more")
        if has_more is None:
            has_more = (page.get("pagination") or {}).get("has_more")
        next_cursor = page.get("next_cursor") \
            or (page.get("pagination") or {}).get("next_cursor")
        if not has_more or not next_cursor:
            break
        cursor = next_cursor
        log.debug("paginating: page %d, next cursor=%s", pages, cursor)
    if merged is not None:
        merged.pop("next_cursor", None)
        merged["has_more"] = False
        merged["_pages_fetched"] = pages
        # Data-style payloads carry pagination state in a nested object that
        # the renderer reads from; reset it too so a fully-followed result
        # does not still advertise a stale next_cursor / has_more.
        nested = merged.get("pagination")
        if isinstance(nested, dict):
            nested.pop("next_cursor", None)
            nested["has_more"] = False
    return merged


# --------------------------------------------------------------------------
# Output rendering
# --------------------------------------------------------------------------
def _scalar(value, width=600):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    if len(text) > width:
        text = text[:width] + f"... ({len(text)} chars)"
    return text.replace("\n", "\\n") if len(text) > 120 else text


def _human(value, indent=0):
    pad = "  " * indent
    if isinstance(value, dict):
        for key, val in value.items():
            if isinstance(val, (dict, list)) and val:
                print(f"{pad}{key}:")
                _human(val, indent + 1)
            else:
                print(f"{pad}{key}: {_scalar(val)}")
    elif isinstance(value, list):
        if not value:
            print(f"{pad}(empty)")
        for i, item in enumerate(value):
            if isinstance(item, (dict, list)):
                print(f"{pad}[{i}]")
                _human(item, indent + 1)
            else:
                print(f"{pad}- {_scalar(item)}")
    else:
        print(f"{pad}{_scalar(value)}")


def render(obj, as_json):
    """Print a result either as raw JSON or in a human-readable form."""
    if as_json:
        if isinstance(obj, bytes):
            sys.stdout.buffer.write(obj)
        else:
            print(json.dumps(obj, indent=2, ensure_ascii=False))
        return

    if isinstance(obj, bytes):
        print(f"<{len(obj)} bytes of binary data>")
        return
    if not isinstance(obj, (dict, list)):
        print(obj)
        return

    # Search-style payload: results + total_count + ...
    if isinstance(obj, dict) and isinstance(obj.get("results"), list):
        results = obj["results"]
        total = obj.get("total_count", len(results))
        print(f"== {len(results)} result(s) shown / {total} total"
              f"  ({obj.get('query_time_ms', '?')} ms)"
              f"  has_more={obj.get('has_more')} ==")
        if obj.get("bulk_search_meta"):
            print("-- bulk_search_meta --")
            _human(obj["bulk_search_meta"], 1)
        for i, item in enumerate(results):
            src = item.get("_source", item) if isinstance(item, dict) else item
            print(f"\n[{i}] " + "-" * 60)
            _human(src, 1)
        if obj.get("next_cursor"):
            print(f"\nnext_cursor: {obj['next_cursor']}")
        return

    # Data-style payload (per-sample strings/functions).
    if isinstance(obj, dict) and isinstance(obj.get("data"), list):
        data = obj["data"]
        pg = obj.get("pagination", {})
        print(f"== {len(data)} item(s) shown / {pg.get('total', '?')} total"
              f"  has_more={pg.get('has_more')} ==")
        for i, item in enumerate(data):
            print(f"\n[{i}] " + "-" * 60)
            _human(item, 1)
        if pg.get("next_cursor"):
            print(f"\nnext_cursor: {pg['next_cursor']}")
        return

    _human(obj)


@contextlib.contextmanager
def _output_to(path):
    """Redirect stdout to `path` for the block, or no-op when `path` is None."""
    if not path:
        yield
        return
    try:
        fh = open(path, "w", encoding="utf-8")
    except OSError as exc:
        raise REDSError(f"Cannot write '{path}': {exc.strerror or exc}")
    with fh, contextlib.redirect_stdout(fh):
        yield


def emit_error(exc, as_json):
    """Print an error to stderr; structured JSON when --json is set."""
    if as_json:
        payload = {"error": True, "message": str(exc)}
        if isinstance(exc, REDSAPIError):
            payload.update(status=exc.status, code=exc.code,
                           message=exc.message, detail=exc.detail)
        print(json.dumps(payload, indent=2), file=sys.stderr)
    else:
        print(f"error: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------
# Operator / schema reference (printed by the `operators` subcommand)
# --------------------------------------------------------------------------
OPERATOR_HELP = """\
REDS search operators (use with `search`, `code-search`, `strings-search`)
==========================================================================

  OPERATOR      SYNTAX              MEANING
  ------------  ------------------  --------------------------------------
  Partial       field:"value"       Case-insensitive whole-word match
  Exact         field="value"       Exact value match
  Numeric >     field:>N            Greater than
  Numeric <     field:<N            Less than
  AND           +field:"value"      Term must be included
  OR            |field:"value"      Either term matches
  NOT           -field="value"      Term must be excluded

Rules
  * AND (+) and OR (|) operators cannot be mixed in one query (HTTP 400).
  * String partial match  string:"x"  -> returns string metadata.
  * String exact match    string="x"  -> returns sample hashes.
  * Regex (::) is web-UI only, not available in API v1.

Example queries
  filetype_magika="pebin"
  filesize:>100000 +is_packed=1
  packer="UPX" |packer="KByS"
  has_overlay=1 -language:"go"
  compiler:"Visual Basic"
  string="GetProcAddress"
  ipv4="192.168.1.100" +filetype_magika="pebin"
  cve="CVE-2021-44228"
  section_entropy:>7.999
  is_debuggable=1 +min_sdk_version:<=19          (APK)
  eval_count:>=1 +atob_count:>=1                 (JavaScript)

Field families (see `fields` for the live, complete list)
  Common      sha256 md5 sha1 filesize file_entropy filetype filetype_magika
              filetype_mime first_seen is_fat parent_sha256 child_sha256
  Malcontent  malcontent_risk_score malcontent_risk_level malcontent_behavior_id
              malcontent_rule_name malcontent_description
  Capa        namespace capability tactic technique technique_id objective
              behavior behavior_id
  DIE         compiler language packer protector linker library installer
              operation_system tool sfx stub joiner is_packed  (+ *_full)
  Hashes      ssdeep_hash tlsh_hash imphash authentihash richhash imphash
              import_hash export_hash macho_import_hash permhash ...
  IOCs        ipv4 ipv6 fqdn url email server hash_md5 hash_sha1 hash_sha256
              cve cwe cpe crypto_btc crypto_eth crypto_xrp crypto_bch
              crypto_ada crypto_substrate path_linux path_windows
              registry_key onion
  YARA        rule_name
  Strings     string string_encoding string_length string_entropy
  PE          compilation_time_utc is_dotnet is_signed has_overlay
              number_of_sections number_of_imports architecture type
              section_* resource_* overlay_* certificate_* ...
  ELF         ei_class_str e_machine_str is_stripped is_pie has_canary
              has_nx has_relro build_id number_of_* dependency_name ...
  Mach-O      cputype_str filetype_str is_signed uuid load_commands_set
              dylib_name entitlement_key signing_type cd_team_id ...
  APK         package_name app_name version_code min_sdk_version
              is_debuggable permission_name component_type contains_embedded_apk
              certificate_thumbprint lib_is_known_packer test_zip_bomb ...
  JS          is_minified is_likely_obfuscated obfuscator_name
              obfuscation_score obfuscation_techniques eval_count
              api_category api_name detected_environment script_type ...
  Code        decompiled_function decompiled_function_name
              decompiled_function_hash disassembled_function
              disassembled_function_hash decompiled_method_hash
              smali_method_hash   (use the `code-search` subcommand)
"""


# Compact query syntax + examples shown at the bottom of `--help`. Kept short
# on purpose; `operators` prints the full operator and field reference above.
QUERY_HELP_EPILOG = """\
Search query syntax  (for the search, code-search and strings-search commands)
  field:"value"   partial match - case-insensitive whole word
  field="value"   exact match
  field:>N        numeric greater-than        field:<N   numeric less-than
  +term           AND - term required         |term      OR - either term
  -term           NOT - term excluded
  AND (+) and OR (|) operators cannot be mixed in a single query.

Example queries
  reds_client.py search 'filetype_magika="pebin"'
  reds_client.py search 'filetype:"PE32" +filesize:>100000'
  reds_client.py search 'packer="UPX" |packer="KByS"'
  reds_client.py search 'is_packed=1 -language:"go"'
  reds_client.py search 'cve="CVE-2021-44228"'
  reds_client.py search 'string="GetProcAddress"'     (exact -> sample hashes)
  reds_client.py code-search 'decompiled_function:"CreateFile"'
  reds_client.py file <sha256>                        (full sample details)
  reds_client.py iocs <sha256> --summary

Run `reds_client.py operators` for the full operator and schema-field reference.
"""


# --------------------------------------------------------------------------
# Subcommand handlers
# --------------------------------------------------------------------------
def cmd_search(client, args):
    check_query(args.query)
    if args.all:
        return paginate(
            lambda c: client.search(args.query, cursor=c, fields=args.fields),
            max_pages=args.max_pages)
    return client.search(args.query, cursor=args.cursor, fields=args.fields,
                          fmt=args.format)


def cmd_code_search(client, args):
    check_query(args.query)
    if args.all:
        return paginate(lambda c: client.code_search(args.query, cursor=c),
                        max_pages=args.max_pages)
    return client.code_search(args.query, cursor=args.cursor)


def cmd_strings_search(client, args):
    check_query(args.query)
    if args.all:
        return paginate(lambda c: client.strings_search(args.query, cursor=c),
                        max_pages=args.max_pages)
    return client.strings_search(args.query, cursor=args.cursor)


def cmd_strings_samples(client, args):
    return client.strings_samples(args.string, offset=args.offset,
                                  limit=args.limit)


def cmd_bulk_search(client, args):
    values = list(args.values or [])
    if args.values_file:
        try:
            with open(args.values_file, "r", encoding="utf-8") as fh:
                values += [line.strip() for line in fh if line.strip()]
        except OSError as exc:
            raise REDSError(f"Cannot read values file '{args.values_file}': "
                            f"{exc.strerror or exc}")
    if not values:
        raise REDSError("bulk-search needs values via --values or --values-file.")
    if len(values) > 300:
        raise REDSError(f"bulk-search accepts at most 300 values "
                        f"({len(values)} given).")
    return client.bulk_search(args.field, values, cursor=args.cursor)


def cmd_bulk_fields(client, args):
    return client.bulk_search_fields()


def cmd_file(client, args):
    return client.file(validate_hash(args.hash))


def cmd_collections(client, args):
    return client.collections()


def cmd_fields(client, args):
    return client.fields(collection=args.collection)


def cmd_stats(client, args):
    return client.stats()


def cmd_quota(client, args):
    return client.quota()


def cmd_validate(client, args):
    return client.validation(validate_hash(args.sha256, sha256_only=True))


def cmd_code_stats(client, args):
    return client.code_statistics(validate_hash(args.sha256, sha256_only=True))


def cmd_functions(client, args):
    sha = validate_hash(args.sha256, sha256_only=True)
    if args.all:
        return paginate(
            lambda c: client.functions(sha, args.kind, cursor=c or 0,
                                        limit=args.limit),
            max_pages=args.max_pages)
    return client.functions(sha, args.kind, cursor=args.cursor,
                            limit=args.limit)


def cmd_string_stats(client, args):
    return client.string_statistics(validate_hash(args.sha256,
                                                  sha256_only=True))


def cmd_sample_strings(client, args):
    sha = validate_hash(args.sha256, sha256_only=True)
    common = dict(search=args.search, encoding=args.encoding,
                  min_entropy=args.min_entropy, max_entropy=args.max_entropy)
    if args.all:
        return paginate(
            lambda c: client.sample_strings(sha, cursor=c, limit=args.limit,
                                             **common),
            max_pages=args.max_pages)
    return client.sample_strings(sha, cursor=args.cursor, limit=args.limit,
                                 **common)


def cmd_iocs(client, args):
    sha = validate_hash(args.sha256, sha256_only=True)
    if args.summary:
        return client.iocs_summary(sha)
    return client.iocs(sha, include_counts=not args.no_counts,
                       ioc_types=args.types)


def cmd_upload(client, args):
    path = args.file
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise REDSError(f"Cannot read file '{path}': {exc.strerror or exc}")
    if not data:
        raise REDSError(f"File '{path}' is empty; nothing to upload.")
    filename = os.path.basename(path) or "sample"
    return client.upload(data, filename, private=args.private)


def cmd_analyze(client, args):
    return client.analyze_sample(validate_hash(args.sha256, sha256_only=True))


def cmd_analyze_code(client, args):
    return client.analyze_code(validate_hash(args.sha256, sha256_only=True))


def cmd_job(client, args):
    return client.job(args.job_id)


def cmd_jobs(client, args):
    return client.jobs(status=args.status, limit=args.limit,
                       offset=args.offset)


def cmd_queue(client, args):
    return client.queue_status()


def cmd_download(client, args):
    h = validate_hash(args.hash)
    blob = client.download(h)
    out_path = args.output or f"{h}.zip"
    try:
        with open(out_path, "wb") as fh:
            fh.write(blob)
    except OSError as exc:
        raise REDSError(f"Cannot write '{out_path}': {exc.strerror or exc}")
    result = {"saved": out_path, "bytes": len(blob),
              "zip_password": ZIP_PASSWORD.decode()}
    if args.extract:
        dest = args.extract_dir or "."
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                zf.extractall(path=dest, pwd=ZIP_PASSWORD)
                result["extracted_to"] = dest
                result["extracted_files"] = zf.namelist()
        except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
            raise REDSError(f"Failed to extract ZIP to '{dest}': {exc}")
    return result


def cmd_operators(client, args):
    print(OPERATOR_HELP)
    return None


HANDLERS = {
    "search": cmd_search,
    "code-search": cmd_code_search,
    "strings-search": cmd_strings_search,
    "strings-samples": cmd_strings_samples,
    "bulk-search": cmd_bulk_search,
    "bulk-fields": cmd_bulk_fields,
    "file": cmd_file,
    "collections": cmd_collections,
    "fields": cmd_fields,
    "stats": cmd_stats,
    "quota": cmd_quota,
    "validate": cmd_validate,
    "code-stats": cmd_code_stats,
    "functions": cmd_functions,
    "string-stats": cmd_string_stats,
    "sample-strings": cmd_sample_strings,
    "iocs": cmd_iocs,
    "upload": cmd_upload,
    "analyze": cmd_analyze,
    "analyze-code": cmd_analyze_code,
    "job": cmd_job,
    "jobs": cmd_jobs,
    "queue": cmd_queue,
    "download": cmd_download,
    "operators": cmd_operators,
}

# Subcommands that do not require an API token / network call.
OFFLINE_COMMANDS = {"operators"}


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------
def build_parser():
    # Global flags live on a shared parent so they work both before and after
    # the subcommand. They use SUPPRESS defaults so a subparser copy does not
    # clobber a value already set on the main parser; real defaults are
    # applied after parsing (see apply_global_defaults).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--debug", action="store_true",
                        default=argparse.SUPPRESS,
                        help="enable verbose debug logging to stderr")
    common.add_argument("--json", dest="json_out", action="store_true",
                        default=argparse.SUPPRESS,
                        help="emit raw JSON output")
    common.add_argument("--api-key", metavar="TOKEN",
                        default=argparse.SUPPRESS,
                        help="API token (overrides env var and Keychain)")
    common.add_argument("--timeout", type=int, metavar="SEC",
                        default=argparse.SUPPRESS,
                        help="HTTP request timeout in seconds (default 60)")
    common.add_argument("-o", "--output", metavar="FILE",
                        default=argparse.SUPPRESS,
                        help="write the result to FILE instead of stdout "
                             "(for `download`: the saved ZIP path, "
                             "default <hash>.zip)")

    parser = argparse.ArgumentParser(
        prog="reds_client.py", parents=[common],
        description="Command-line client for the RationalEdge DataSet (REDS) "
                    "API v1.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=QUERY_HELP_EPILOG)
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    parser.add_argument("--usage", action="store_true",
                        help="show current quota usage and limits and exit "
                             "(alias for the `quota` command)")
    parser.add_argument("--set-api-key", action="store_true",
                        help="store an API token in the macOS Keychain "
                             "(prompts securely) and exit")
    parser.add_argument("--delete-api-key", action="store_true",
                        help="remove the stored API token from the Keychain "
                             "and exit")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    def add(name, help_text, epilog=None):
        kwargs = dict(parents=[common], help=help_text, description=help_text)
        if epilog:
            kwargs["epilog"] = epilog
            # Preserve the table/example layout instead of re-wrapping it.
            kwargs["formatter_class"] = argparse.RawDescriptionHelpFormatter
        return sub.add_parser(name, **kwargs)

    p = add("search", "Search across all collections with the query language.",
            epilog=QUERY_HELP_EPILOG)
    p.add_argument("query", help='e.g. \'filetype_magika="pebin" '
                                 '+filesize:>100000\'')
    p.add_argument("--fields", help="comma-separated fields to include")
    p.add_argument("--cursor", help="pagination cursor")
    p.add_argument("--format", choices=["json", "ndjson"],
                   help="response format")
    p.add_argument("--all", action="store_true",
                   help="follow cursors and merge all pages")
    p.add_argument("--max-pages", type=int, default=50,
                   help="page cap for --all (default 50)")

    p = add("code-search", "Search decompiled / disassembled functions.",
            epilog=QUERY_HELP_EPILOG)
    p.add_argument("query", help='e.g. \'decompiled_function:"CreateFile"\'')
    p.add_argument("--cursor")
    p.add_argument("--all", action="store_true")
    p.add_argument("--max-pages", type=int, default=50)

    p = add("strings-search", "Browse strings across the dataset.",
            epilog=QUERY_HELP_EPILOG)
    p.add_argument("query", help='e.g. \'string:"password"\'')
    p.add_argument("--cursor")
    p.add_argument("--all", action="store_true")
    p.add_argument("--max-pages", type=int, default=50)

    p = add("strings-samples", "List samples containing an exact string.")
    p.add_argument("string", help="raw string value (no quotes needed)")
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--limit", type=int, default=20)

    p = add("bulk-search", "Search many exact values of one field at once.")
    p.add_argument("--field", required=True,
                   help="field name (see `bulk-fields`)")
    p.add_argument("--values", nargs="+", help="values to look up")
    p.add_argument("--values-file", help="file with one value per line")
    p.add_argument("--cursor")

    add("bulk-fields", "List fields available for bulk-search.")

    p = add("file", "Look up full sample details by MD5/SHA1/SHA256 hash.")
    p.add_argument("hash", help="MD5, SHA1 or SHA256 hash")

    add("collections", "List available collections.")

    p = add("fields", "List searchable fields (optionally for one collection).")
    p.add_argument("--collection", help="restrict to one collection")

    add("stats", "Get dataset statistics.")
    add("quota", "Get current quota usage.")

    p = add("validate", "Check code-analysis data availability for a sample.")
    p.add_argument("sha256")

    p = add("code-stats", "Get code-analysis statistics for a sample.")
    p.add_argument("sha256")

    p = add("functions", "Get decompiled/disassembled functions of a sample.")
    p.add_argument("sha256")
    p.add_argument("--kind", choices=["decompiled", "disassembled"],
                   default="decompiled")
    p.add_argument("--cursor", type=int, default=0)
    p.add_argument("--limit", type=int, default=50, help="1-100")
    p.add_argument("--all", action="store_true")
    p.add_argument("--max-pages", type=int, default=50)

    p = add("string-stats", "Get string statistics for a sample.")
    p.add_argument("sha256")

    p = add("sample-strings", "Get the strings extracted from a sample.")
    p.add_argument("sha256")
    p.add_argument("--search", help="filter strings by substring")
    p.add_argument("--encoding", help="e.g. AsciiString, Utf16String")
    p.add_argument("--min-entropy", type=float)
    p.add_argument("--max-entropy", type=float)
    p.add_argument("--cursor")
    p.add_argument("--limit", type=int, default=500, help="1-1000")
    p.add_argument("--all", action="store_true")
    p.add_argument("--max-pages", type=int, default=50)

    p = add("iocs", "Get IOCs extracted from a sample.")
    p.add_argument("sha256")
    p.add_argument("--summary", action="store_true",
                   help="counts per IOC type only")
    p.add_argument("--types", help="comma-separated IOC types to include")
    p.add_argument("--no-counts", action="store_true",
                   help="skip per-IOC occurrence counts (faster)")

    p = add("upload", "Upload a local malware sample for analysis (<=100MB).")
    p.add_argument("file", help="path to the file to upload")
    p.add_argument("--private", action="store_true",
                   help="mark the upload as private (requires premium "
                        "subscription)")

    p = add("analyze", "Queue analysis for a catalog-only sample.")
    p.add_argument("sha256")

    p = add("analyze-code", "Queue code analysis for an analysed sample.")
    p.add_argument("sha256")

    p = add("job", "Get the status of an analysis job.")
    p.add_argument("job_id")

    p = add("jobs", "List analysis jobs for the authenticated user.")
    p.add_argument("--status",
                   choices=["queued", "running", "completed", "failed"])
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--offset", type=int, default=0)

    add("queue", "Get analysis queue status.")

    p = add("download", "Download a sample as a password-protected ZIP "
                        "(use -o/--output for the path, default <hash>.zip).")
    p.add_argument("hash", help="MD5, SHA1 or SHA256 hash")
    p.add_argument("--extract", action="store_true",
                   help="extract the ZIP (password: infected)")
    p.add_argument("--extract-dir", help="extraction directory")

    add("operators", "Print the query operator and schema field reference.")

    return parser


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def handle_set_api_key(args):
    """Prompt for and store an API token in the Keychain."""
    import getpass
    token = args.api_key
    if not token:
        try:
            token = getpass.getpass("Enter REDS API token: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\naborted.", file=sys.stderr)
            return 1
    if not token:
        print("error: no token provided.", file=sys.stderr)
        return 1
    keychain_set_token(token)
    print(f"API token stored in Keychain (service '{KEYCHAIN_SERVICE}').")
    return 0


def apply_global_defaults(args):
    """Fill in defaults for global flags that use SUPPRESS in the parser."""
    for name, default in (("debug", False), ("json_out", False),
                          ("api_key", None), ("timeout", 60), ("output", None)):
        if not hasattr(args, name):
            setattr(args, name, default)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    apply_global_defaults(args)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="[debug] %(message)s", stream=sys.stderr)

    # Key management flags run and exit before anything else.
    if args.set_api_key:
        try:
            return handle_set_api_key(args)
        except REDSError as exc:
            emit_error(exc, args.json_out)
            return 1
    if args.delete_api_key:
        try:
            if keychain_delete_token():
                print("API token removed from Keychain.")
            else:
                print("No stored API token found.", file=sys.stderr)
            return 0
        except REDSError as exc:
            emit_error(exc, args.json_out)
            return 1

    # `--usage` is a convenience alias for the `quota` command.
    if args.usage:
        args.command = "quota"

    if not args.command:
        parser.print_help()
        return 1

    # `download` writes its own file via --output, so it manages output itself;
    # for every other command, -o/--output redirects the rendered result.
    out_path = None if args.command == "download" else args.output
    handler = HANDLERS[args.command]
    try:
        if args.command in OFFLINE_COMMANDS:
            with _output_to(out_path):
                handler(None, args)
        else:
            token = resolve_token(args.api_key)
            client = REDSClient(token, timeout=args.timeout)
            result = handler(client, args)
            with _output_to(out_path):
                if result is not None:
                    render(result, args.json_out)
        if out_path:
            print(f"output written to {out_path}", file=sys.stderr)
        return 0
    except REDSAPIError as exc:
        emit_error(exc, args.json_out)
        # Map a few statuses to distinct exit codes for scripting.
        return {401: 3, 403: 3, 404: 4, 429: 5}.get(exc.status, 2)
    except REDSError as exc:
        emit_error(exc, args.json_out)
        return 2
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("\ninterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:  # last-resort guard: never show users a traceback
        log.debug("unexpected error", exc_info=True)
        emit_error(REDSError(f"unexpected error: {exc}"), args.json_out)
        return 2


if __name__ == "__main__":
    sys.exit(main())
