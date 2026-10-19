"use strict";
// proof-audit core library. Zero dependencies; Node >= 18.
// Validates findings files and checks every cited location against the real source tree.

const fs = require("node:fs");
const path = require("node:path");

const VERDICTS = ["confirmed", "needs_validation", "rejected"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const ROLES = ["entrypoint", "propagation", "control", "sink", "evidence"];
const COVERAGE_STATUSES = ["hunted", "skipped", "out_of_scope"];
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$/;
const CWE_RE = /^CWE-[1-9][0-9]{0,4}$/;
const MIN_QUOTE_CHARS = 6;
const MAX_FILE_BYTES = 5 * 1024 * 1024;
/** Largest allowed end_line - line. Stops a citation from "covering" a whole file. */
const MAX_SPAN = 50;
/** --fix only moves a citation this far, unless all drifted locations of a finding moved by the same offset. */
const MAX_FIX_DISTANCE = 30;
const IDENT = /[\p{L}\p{N}\p{Mn}\p{Mc}_$]/u;

// ---------------------------------------------------------------------------
// Input loading and format detection
// ---------------------------------------------------------------------------

/**
 * Accepts the native proof-audit document ({version, findings: [...]}) or a
 * Cloudflare security-audit-skill findings.json (a top-level array whose records
 * use `trace` and `evidence` with file/line but no quotes). Returns
 * { format, doc, findings } where findings use the native shape.
 */
function normalizeDocument(input) {
  if (Array.isArray(input)) {
    return { format: "cloudflare", doc: input, findings: input.map(fromCloudflare) };
  }
  if (input && typeof input === "object" && Array.isArray(input.findings)) {
    return { format: "native", doc: input, findings: input.findings };
  }
  throw new Error("findings file must be {\"version\":1,\"findings\":[...]} or a Cloudflare-style array");
}

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function fromCloudflare(rec, i) {
  if (!isObj(rec)) return rec; // left as-is; verifyFindings fails it
  const locs = [];
  for (const t of Array.isArray(rec.trace) ? rec.trace : []) {
    locs.push(isObj(t) ? { role: t.kind, file: t.file, line: t.line, note: t.description } : t);
  }
  for (const e of Array.isArray(rec.evidence) ? rec.evidence : []) {
    locs.push(isObj(e) ? { role: "evidence", file: e.file, line: e.line, note: e.description } : e);
  }
  return {
    id: typeof rec.fingerprint === "string" ? rec.fingerprint : `record-${i + 1}`,
    verdict: rec.verdict,
    title: typeof rec.title === "string" ? rec.title : undefined,
    severity: isObj(rec.severity) ? rec.severity.overall_severity : rec.severity,
    locations: locs,
  };
}

// ---------------------------------------------------------------------------
// Path rules (shared by validate and verify)
// ---------------------------------------------------------------------------

/** A single leading "./" is tolerated (models add it often) and ignored. */
function cleanPath(file) {
  return typeof file === "string" && file.startsWith("./") ? file.slice(2) : file;
}

/** Returns null if the cited path is syntactically acceptable, else {code, detail}. */
function pathSyntaxError(rawFile) {
  const file = cleanPath(rawFile);
  if (typeof file !== "string" || file.length === 0) return { code: "PATH_INVALID", detail: "empty path" };
  if (/[\0-\x1f\x7f]/.test(file)) return { code: "PATH_INVALID", detail: "control character in path" };
  if (path.posix.isAbsolute(file) || path.win32.isAbsolute(file) || /^[A-Za-z]:/.test(file))
    return { code: "PATH_ESCAPE", detail: "absolute paths are not allowed; cite repository-relative paths" };
  if (file.includes("\\")) return { code: "PATH_INVALID", detail: "use forward slashes" };
  const parts = file.split("/");
  if (parts.includes("..")) return { code: "PATH_ESCAPE", detail: "'..' segments are not allowed" };
  if (parts.some((p) => p === "" || p === ".")) return { code: "PATH_INVALID", detail: "empty or '.' path segment (or trailing slash)" };
  if (parts.some((p) => /[. ]$/.test(p))) return { code: "PATH_INVALID", detail: "segment ends with '.' or space" };
  return null;
}

// ---------------------------------------------------------------------------
// Schema validation (native format)
// ---------------------------------------------------------------------------

function isNonEmptyString(v) {
  return typeof v === "string" && v.trim().length > 0;
}

function quoteChars(quote) {
  return quote.replace(/\s/g, "").length;
}

/**
 * opts.citations === false skips the per-location file/line/end_line/quote rules,
 * because `verify` checks those itself and reports a specific failure code.
 */
function validateDocument(input, opts = {}) {
  const citations = opts.citations !== false;
  const errors = [];
  const err = (where, msg) => errors.push(`${where}: ${msg}`);

  if (!isObj(input)) {
    err("$", "must be an object with version and findings");
    return errors;
  }
  if (input.version !== 1) err("$.version", "must be 1");
  if (input.target !== undefined) {
    if (!isObj(input.target)) err("$.target", "must be an object");
    else {
      if (input.target.name !== undefined && typeof input.target.name !== "string") err("$.target.name", "must be a string");
      if (input.target.source_ref !== undefined && !isNonEmptyString(input.target.source_ref)) err("$.target.source_ref", "must be a non-empty string");
    }
  }
  if (input.coverage !== undefined) {
    if (!Array.isArray(input.coverage)) err("$.coverage", "must be an array");
    else {
      const units = new Set();
      input.coverage.forEach((c, i) => {
        const at = `$.coverage[${i}]`;
        if (!isObj(c)) return err(at, "must be an object");
        if (!isNonEmptyString(c.unit) || !ID_RE.test(c.unit)) err(`${at}.unit`, "must match " + ID_RE);
        else if (units.has(c.unit)) err(`${at}.unit`, `duplicate unit ${c.unit}`);
        else units.add(c.unit);
        if (!COVERAGE_STATUSES.includes(c.status)) err(`${at}.status`, `must be one of ${COVERAGE_STATUSES.join(", ")}`);
        if (c.status !== "hunted" && !isNonEmptyString(c.note)) err(`${at}.note`, `${c.status} units must say why`);
        if (c.checked !== undefined && (!Array.isArray(c.checked) || !c.checked.every(isNonEmptyString)))
          err(`${at}.checked`, "must be an array of non-empty strings");
        if (c.note !== undefined && typeof c.note !== "string") err(`${at}.note`, "must be a string");
      });
    }
  }
  if (!Array.isArray(input.findings)) {
    err("$.findings", "must be an array");
    return errors;
  }

  const seen = new Set();
  input.findings.forEach((f, i) => {
    const at = `$.findings[${i}]`;
    if (!isObj(f)) return err(at, "must be an object");
    if (!isNonEmptyString(f.id) || !ID_RE.test(f.id)) err(`${at}.id`, "must match " + ID_RE);
    else if (seen.has(f.id)) err(`${at}.id`, `duplicate id ${f.id}`);
    else seen.add(f.id);
    if (!VERDICTS.includes(f.verdict)) return err(`${at}.verdict`, `must be one of ${VERDICTS.join(", ")}`);
    for (const k of ["title", "summary"]) if (!isNonEmptyString(f[k])) err(`${at}.${k}`, "required non-empty string");
    if (f.cwe !== undefined && (typeof f.cwe !== "string" || !CWE_RE.test(f.cwe))) err(`${at}.cwe`, "must look like CWE-89");
    if (f.unit !== undefined && (!isNonEmptyString(f.unit) || !ID_RE.test(f.unit))) err(`${at}.unit`, "must match " + ID_RE);

    if (f.verdict === "confirmed") {
      if (!SEVERITIES.includes(f.severity)) err(`${at}.severity`, `confirmed findings need severity: ${SEVERITIES.join(", ")}`);
      if (!isObj(f.boundary) || !isNonEmptyString(f.boundary.attacker) || !isNonEmptyString(f.boundary.asset))
        err(`${at}.boundary`, "confirmed findings need boundary.attacker and boundary.asset");
      if (!isNonEmptyString(f.remediation)) err(`${at}.remediation`, "confirmed findings need a remediation");
    } else if (f.severity !== undefined) {
      err(`${at}.severity`, `only confirmed findings carry severity (verdict is ${f.verdict})`);
    }
    if (f.verdict === "needs_validation" && !isNonEmptyString(f.blocker)) err(`${at}.blocker`, "needs_validation findings must name the unresolved fact");
    if (f.verdict === "rejected" && !isNonEmptyString(f.reason)) err(`${at}.reason`, "rejected findings must say why");

    if (!Array.isArray(f.locations) || f.locations.length === 0) {
      err(`${at}.locations`, "must be a non-empty array");
      return;
    }
    f.locations.forEach((l, j) => {
      const la = `${at}.locations[${j}]`;
      if (!isObj(l)) return err(la, "must be an object");
      if (!ROLES.includes(l.role)) err(`${la}.role`, `must be one of ${ROLES.join(", ")}`);
      if (!citations) return;
      if (!isNonEmptyString(l.file)) err(`${la}.file`, "required");
      else {
        const pe = pathSyntaxError(l.file);
        if (pe) err(`${la}.file`, pe.detail);
      }
      if (!Number.isInteger(l.line) || l.line < 1) err(`${la}.line`, "must be a positive integer");
      if (l.end_line !== undefined) {
        if (!Number.isInteger(l.end_line) || !Number.isInteger(l.line) || l.end_line < l.line) err(`${la}.end_line`, "must be an integer >= line");
        else if (l.end_line - l.line > MAX_SPAN) err(`${la}.end_line`, `may be at most ${MAX_SPAN} lines after line`);
      }
      if (!isNonEmptyString(l.quote)) err(`${la}.quote`, "required: copy the cited source text verbatim");
      else if (quoteChars(l.quote) < MIN_QUOTE_CHARS) err(`${la}.quote`, `needs at least ${MIN_QUOTE_CHARS} non-space characters`);
      if (l.note !== undefined && typeof l.note !== "string") err(`${la}.note`, "must be a string");
    });
    if (f.verdict === "confirmed") {
      const roles = new Set(f.locations.map((l) => isObj(l) && l.role));
      if (!roles.has("entrypoint")) err(`${at}.locations`, "confirmed findings need an entrypoint location");
      if (!roles.has("sink")) err(`${at}.locations`, "confirmed findings need a sink location");
    }
  });
  return errors;
}

// ---------------------------------------------------------------------------
// Citation verification
// ---------------------------------------------------------------------------

function normalizeLine(s) {
  return s.replace(/\s+/g, " ").trim();
}

/** Split a quote into normalized lines (leading/trailing blank lines dropped). */
function quoteLines(quote) {
  const lines = quote.split(/\r\n|\r|\n/).map(normalizeLine);
  while (lines.length && lines[0] === "") lines.shift();
  while (lines.length && lines[lines.length - 1] === "") lines.pop();
  return lines;
}

/**
 * Is `needle` inside `hay` at a position where it does not cut an identifier in
 * half? (`exec(` must not match inside `safe_exec(`.) When `anchor` is "end" the
 * match must reach the end of hay; "start" means it must begin at index 0.
 */
function containsAtBoundary(hay, needle, anchor) {
  if (needle === "") return true;
  const starts = [];
  if (anchor === "start") {
    if (hay.startsWith(needle)) starts.push(0);
  } else if (anchor === "end") {
    if (hay.endsWith(needle)) starts.push(hay.length - needle.length);
  } else {
    for (let i = hay.indexOf(needle); i !== -1; i = hay.indexOf(needle, i + 1)) starts.push(i);
  }
  return starts.some((i) => {
    const before = i > 0 ? hay[i - 1] : "";
    const after = hay[i + needle.length] || "";
    if (IDENT.test(needle[0]) && before && IDENT.test(before)) return false;
    if (IDENT.test(needle[needle.length - 1]) && after && IDENT.test(after)) return false;
    return true;
  });
}

/**
 * Does the normalized quote occur in fileNorm starting at 0-based index `start`?
 * One line: a substring of that line on identifier boundaries.
 * Several lines: contiguous; the first quote line must end its file line, middle
 * lines must equal the file lines, and the last must start its file line - except
 * that the first and last lines may stop short when the rest of that file line is
 * only a trailing comment or the start of the quote is preceded only by code on
 * the same line. To keep that simple and predictable, the first line may be any
 * boundary-respecting substring that runs to the end of the file line OR is
 * followed only by a comment; the last line may be any boundary-respecting prefix.
 */
function matchesAt(fileNorm, q, start) {
  if (start < 0 || start + q.length > fileNorm.length) return false;
  if (q.length === 1) return containsAtBoundary(fileNorm[start], q[0]);
  const first = fileNorm[start];
  const okFirst = containsAtBoundary(first, q[0], "end") || containsAtBoundary(stripTrailingComment(first), q[0], "end");
  if (!okFirst) return false;
  for (let k = 1; k < q.length - 1; k++) if (fileNorm[start + k] !== q[k]) return false;
  const last = fileNorm[start + q.length - 1];
  return containsAtBoundary(last, q[q.length - 1], "start");
}

/** True if every ", ' and ` in s is closed (ignoring backslash-escaped ones), i.e. s does not end inside a string. */
function quotesBalanced(s) {
  let open = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\") {
      i++;
      continue;
    }
    if (open) {
      if (c === open) open = null;
    } else if (c === '"' || c === "'" || c === "`") open = c;
  }
  return open === null;
}

/**
 * Remove a trailing `// ...`, `# ...`, `-- ...` or `/* ...` comment from a normalized
 * line. Only used to let a multi-line quote's first line stop before a comment.
 * A marker inside a string literal is not a comment, so the code before the marker
 * must have balanced quotes.
 */
function stripTrailingComment(line) {
  const re = /\s+(?:\/\/|#|--|\/\*)/g;
  for (let m = re.exec(line); m; m = re.exec(line)) {
    const before = line.slice(0, m.index);
    if (/\S/.test(before) && quotesBalanced(before)) return before;
  }
  return line;
}

function findAll(fileNorm, q) {
  const hits = [];
  for (let i = 0; i + q.length <= fileNorm.length; i++) if (matchesAt(fileNorm, q, i)) hits.push(i + 1);
  return hits;
}

/** Check that every segment of the cited path exists with exactly this spelling (catches case-insensitive and Win32 name folding). */
function exactCase(rootReal, file) {
  let dir = rootReal;
  for (const seg of file.split("/")) {
    let names;
    try {
      names = fs.readdirSync(dir);
    } catch {
      return false;
    }
    if (!names.includes(seg)) return false;
    dir = path.join(dir, seg);
  }
  return true;
}

function resolveInside(rootReal, rawFile) {
  const pe = pathSyntaxError(rawFile);
  const file = cleanPath(rawFile);
  if (pe) return { error: pe.code, detail: pe.detail };
  const abs = path.resolve(rootReal, ...file.split("/"));
  let real;
  try {
    real = fs.realpathSync(abs);
  } catch {
    return { error: "FILE_MISSING", detail: "no such file in target" };
  }
  const rel = path.relative(rootReal, real);
  if (rel === "" || rel === ".." || rel.startsWith(".." + path.sep) || path.isAbsolute(rel))
    return { error: "PATH_ESCAPE", detail: "resolves outside the target (symlink?)" };
  if (!exactCase(rootReal, file)) return { error: "FILE_MISSING", detail: "no file with exactly this name (check letter case)" };
  return { real };
}

function makeFileCache() {
  const cache = new Map();
  return (real) => {
    if (cache.has(real)) return cache.get(real);
    let out;
    const st = fs.statSync(real);
    if (!st.isFile()) out = { error: "NOT_A_FILE", detail: "path is not a regular file" };
    else if (st.size > MAX_FILE_BYTES) out = { error: "FILE_TOO_LARGE", detail: `over ${MAX_FILE_BYTES} bytes` };
    else {
      const buf = fs.readFileSync(real);
      if (buf.subarray(0, 8192).includes(0)) out = { error: "NOT_TEXT", detail: "binary file" };
      else {
        const lines = buf.toString("utf8").replace(/^\uFEFF/, "").split(/\r\n|\r|\n/);
        if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
        out = { lines, norm: lines.map(normalizeLine) };
      }
    }
    cache.set(real, out);
    return out;
  };
}

/**
 * Check one location. Returns { status, code, detail, actual_line? } where status
 * is "ok" | "warn" | "fail".
 */
function checkLocation(rootReal, getFile, loc, opts = {}) {
  if (!isObj(loc)) return { status: "fail", code: "LOCATION_INVALID", detail: "location is not an object" };
  const r = resolveInside(rootReal, loc.file);
  if (r.error) return { status: "fail", code: r.error, detail: r.detail };
  let f;
  try {
    f = getFile(r.real);
  } catch (e) {
    return { status: "fail", code: "FILE_MISSING", detail: String(e.message || e) };
  }
  if (f.error) return { status: "fail", code: f.error, detail: f.detail };
  const total = f.lines.length;
  if (!Number.isInteger(loc.line) || loc.line < 1 || loc.line > total)
    return { status: "fail", code: "LINE_OUT_OF_RANGE", detail: `line ${loc.line} but file has ${total} lines` };
  if (loc.end_line !== undefined) {
    if (!Number.isInteger(loc.end_line) || loc.end_line < loc.line || loc.end_line > total)
      return { status: "fail", code: "LINE_OUT_OF_RANGE", detail: `end_line ${loc.end_line} is not between line ${loc.line} and ${total}` };
    if (loc.end_line - loc.line > MAX_SPAN)
      return { status: "fail", code: "LINE_OUT_OF_RANGE", detail: `end_line is more than ${MAX_SPAN} lines after line` };
  }

  if (typeof loc.quote !== "string" || loc.quote.trim() === "") {
    return opts.strict
      ? { status: "fail", code: "QUOTE_MISSING", detail: "no quote; cannot prove the line says what the finding claims" }
      : { status: "warn", code: "QUOTE_MISSING", detail: "file and line exist, but without a quote the content is unverified" };
  }
  const q = quoteLines(loc.quote);
  const chars = quoteChars(q.join(""));
  if (chars < MIN_QUOTE_CHARS)
    return { status: "fail", code: "QUOTE_TOO_SHORT", detail: `quote has ${chars} non-space chars; need ${MIN_QUOTE_CHARS}+ to be meaningful` };

  const end = Math.max(Number.isInteger(loc.end_line) ? loc.end_line : loc.line, loc.line + q.length - 1);
  for (let s = loc.line; s + q.length - 1 <= Math.min(end, total); s++) {
    if (matchesAt(f.norm, q, s - 1)) return { status: "ok", code: "OK", detail: "" };
  }
  const hits = findAll(f.norm, q);
  if (hits.length === 0) return { status: "fail", code: "QUOTE_NOT_FOUND", detail: "quoted text does not appear anywhere in the file" };
  const nearest = hits.reduce((a, b) => (Math.abs(b - loc.line) < Math.abs(a - loc.line) ? b : a));
  if (hits.length === 1)
    return { status: "fail", code: "DRIFTED", detail: `quote is at line ${nearest}, not ${loc.line}`, actual_line: nearest };
  return {
    status: "fail",
    code: "AMBIGUOUS",
    detail: `quote not at line ${loc.line}; it appears ${hits.length} times (${hits.slice(0, 5).join(", ")}${hits.length > 5 ? ", ..." : ""})`,
  };
}

/**
 * Mark DRIFTED locations as fixable when the move is small, or when every drifted
 * location in the finding moved by the same offset (code inserted above them).
 * Far, inconsistent moves become DRIFTED_FAR and are never auto-fixed.
 */
function classifyDrift(checks) {
  const drifted = checks.filter((c) => c.code === "DRIFTED");
  const offsets = new Set(drifted.map((c) => c.actual_line - c.line));
  const sameShift = drifted.length >= 2 && offsets.size === 1;
  for (const c of drifted) {
    if (Math.abs(c.actual_line - c.line) <= MAX_FIX_DISTANCE || sameShift) c.fixable = true;
    else {
      c.code = "DRIFTED_FAR";
      c.detail += `; too far to auto-fix (more than ${MAX_FIX_DISTANCE} lines), re-check that this is the code you meant`;
    }
  }
}

/**
 * Verify all findings. Citations of confirmed and needs_validation findings gate the
 * result; citations of rejected findings are reported but never fail the run.
 * Anything that is not a well-formed rejected finding gates.
 */
function verifyFindings(findings, targetDir, opts = {}) {
  const rootReal = fs.realpathSync(targetDir);
  const getFile = makeFileCache();
  const results = findings.map((f) => {
    const gating = !(isObj(f) && f.verdict === "rejected");
    const locs = isObj(f) && Array.isArray(f.locations) ? f.locations : [];
    const checks = locs.map((loc, idx) => {
      const c = checkLocation(rootReal, getFile, loc, opts);
      return { index: idx, file: isObj(loc) ? loc.file : undefined, line: isObj(loc) ? loc.line : undefined, role: isObj(loc) ? loc.role : undefined, ...c };
    });
    classifyDrift(checks);
    let status = "verified";
    if (!isObj(f) || checks.length === 0 || checks.some((c) => c.status === "fail")) status = "failed";
    else if (checks.some((c) => c.status === "warn")) status = "unquoted";
    return { id: isObj(f) ? f.id : undefined, verdict: isObj(f) ? f.verdict : undefined, title: isObj(f) ? f.title : undefined, gating, status, checks };
  });
  const gatingFailed = results.filter((r) => r.gating && r.status === "failed");
  const summary = {
    findings: results.length,
    verified: results.filter((r) => r.status === "verified").length,
    unquoted: results.filter((r) => r.status === "unquoted").length,
    failed: results.filter((r) => r.status === "failed").length,
    gating_failed: gatingFailed.length,
    locations: results.reduce((n, r) => n + r.checks.length, 0),
    location_failures: results.reduce((n, r) => n + r.checks.filter((c) => c.status === "fail").length, 0),
  };
  return { ok: gatingFailed.length === 0, summary, results };
}

/** Return a deep copy of a native doc with fixable drifted line numbers corrected. */
function applyFixes(doc, verification) {
  const out = JSON.parse(JSON.stringify(doc));
  let fixed = 0;
  verification.results.forEach((r, i) => {
    for (const c of r.checks) {
      if (c.code !== "DRIFTED" || !c.fixable) continue;
      const loc = out.findings[i].locations[c.index];
      const span = Number.isInteger(loc.end_line) ? loc.end_line - loc.line : null;
      loc.line = c.actual_line;
      if (span !== null) loc.end_line = c.actual_line + span;
      fixed++;
    }
  });
  return { doc: out, fixed };
}

// ---------------------------------------------------------------------------
// Report rendering
// ---------------------------------------------------------------------------

const SEV_ORDER = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

function fence(text) {
  const longest = Math.max(2, ...(text.match(/`+/g) || []).map((m) => m.length));
  return "`".repeat(longest + 1);
}

/** Inline code span that survives backticks in the text and needs no escaping inside. */
function codeSpan(s) {
  const text = String(s ?? "").replace(/[\r\n\u2028\u2029]+/g, " ");
  const longest = Math.max(0, ...(text.match(/`+/g) || []).map((m) => m.length));
  const ticks = "`".repeat(longest + 1);
  const pad = text.startsWith("`") || text.endsWith("`") ? " " : "";
  return `${ticks}${pad}${text}${pad}${ticks}`;
}

/** Escape text for use as Markdown prose: one line, no block markers, no inline syntax. */
function md(s) {
  return String(s ?? "")
    .replace(/[\r\n\u2028\u2029]+/g, " ")
    .trim()
    .replace(/([\\`*_[\]<>|~#])/g, "\\$1")
    .replace(/^([-+=])/, "\\$1")
    .replace(/^(\d+)([.)])/, "$1\\$2");
}

/** Remove indentation shared by the 2nd..nth lines; the first line of a quote is often a partial line. */
function dedentQuote(quote) {
  const lines = quote.replace(/\r\n|\r/g, "\n").replace(/\n+$/, "").split("\n");
  const rest = lines.slice(1).filter((l) => l.trim() !== "");
  const indent = rest.length ? Math.min(...rest.map((l) => l.match(/^[ \t]*/)[0].length)) : 0;
  return [lines[0].trim(), ...lines.slice(1).map((l) => l.slice(Math.min(indent, l.match(/^[ \t]*/)[0].length)))];
}

function renderReport(doc, verification) {
  const byId = new Map(verification.results.map((r) => [r.id, r]));
  const ok = (f) => byId.get(f.id)?.status === "verified";
  const confirmed = doc.findings.filter((f) => f.verdict === "confirmed" && ok(f))
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.id.localeCompare(b.id));
  const needs = doc.findings.filter((f) => f.verdict === "needs_validation" && ok(f));
  const excluded = doc.findings.filter((f) => f.verdict !== "rejected" && !ok(f));
  const rejected = doc.findings.filter((f) => f.verdict === "rejected");

  const L = [];
  L.push("# Security audit report", "");
  if (doc.target?.name || doc.target?.source_ref)
    L.push(`Target: ${md(doc.target.name || "(unnamed)")}${doc.target.source_ref ? ` at ${codeSpan(doc.target.source_ref)}` : ""}`, "");
  L.push(
    "Every location quoted below was mechanically checked against the source tree by `proof-audit verify`. " +
      "Findings whose citations did not match the source are listed under *Excluded* and are not reported as vulnerabilities.",
    "",
  );
  const counts = SEVERITIES.map((s) => [s, confirmed.filter((f) => f.severity === s).length]).filter(([, n]) => n);
  L.push("## Summary", "");
  L.push(`| Confirmed | Needs validation | Excluded (citation failures) | Rejected |`, `|---|---|---|---|`);
  L.push(`| ${confirmed.length}${counts.length ? ` (${counts.map(([s, n]) => `${n} ${s}`).join(", ")})` : ""} | ${needs.length} | ${excluded.length} | ${rejected.length} |`, "");

  const renderLocs = (f) => {
    for (const l of f.locations) {
      const range = l.end_line && l.end_line !== l.line ? `${l.line}-${l.end_line}` : `${l.line}`;
      L.push(`- **${md(l.role)}** ${codeSpan(`${l.file}:${range}`)}${l.note ? ` - ${md(l.note)}` : ""}`);
      const fz = fence(l.quote);
      L.push("", `  ${fz}`, ...dedentQuote(l.quote).map((x) => `  ${x}`), `  ${fz}`, "");
    }
  };

  if (confirmed.length) {
    L.push("## Confirmed findings", "");
    for (const f of confirmed) {
      L.push(`### ${md(f.id)}: ${md(f.title)}`, "");
      L.push(`**Severity:** ${f.severity}${f.cwe ? ` | **${f.cwe}**` : ""}`, "");
      L.push(`**Attacker:** ${md(f.boundary.attacker)}  `, `**Asset at risk:** ${md(f.boundary.asset)}`, "");
      L.push(md(f.summary), "", "**Source trace**", "");
      renderLocs(f);
      L.push(`**Fix:** ${md(f.remediation)}`, "");
    }
  }
  if (needs.length) {
    L.push("## Needs validation", "", "These leads are source-grounded but blocked on a fact the source cannot show. They carry no severity.", "");
    for (const f of needs) {
      L.push(`### ${md(f.id)}: ${md(f.title)}`, "", md(f.summary), "", `**Unresolved fact:** ${md(f.blocker)}`, "");
      renderLocs(f);
    }
  }
  if (excluded.length) {
    L.push("## Excluded: citation failures", "", "The auditor proposed these, but their cited source did not check out. Re-investigate before trusting them.", "");
    for (const f of excluded) {
      const r = byId.get(f.id);
      const why = r ? r.checks.filter((c) => c.status !== "ok").map((c) => `${codeSpan(`${c.file}:${c.line}`)} ${c.code}`).join("; ") : "not verified";
      L.push(`- ${md(f.id)}: ${md(f.title)} (${why || "no locations"})`);
    }
    L.push("");
  }
  if (rejected.length) {
    L.push("## Rejected candidates", "");
    for (const f of rejected) L.push(`- ${md(f.id)}: ${md(f.title)} - ${md(f.reason)}`);
    L.push("");
  }
  L.push("## Coverage", "");
  if (Array.isArray(doc.coverage) && doc.coverage.length) {
    const n = (s) => doc.coverage.filter((c) => c.status === s).length;
    L.push(`${doc.coverage.length} planned units: ${n("hunted")} hunted, ${n("skipped")} skipped, ${n("out_of_scope")} out of scope.`, "");
    L.push("| Unit | Status | Findings | Checked / note |", "|---|---|---|---|");
    for (const c of doc.coverage) {
      const ids = doc.findings.filter((f) => f.unit === c.unit).map((f) => md(f.id));
      const detail = [...(c.checked || []).map(md), ...(c.note ? [md(c.note)] : [])].join("; ");
      L.push(`| ${md(c.unit)} | ${c.status} | ${ids.join(", ") || "-"} | ${detail || "-"} |`);
    }
    L.push("");
  } else {
    L.push("No coverage plan was recorded, so this report cannot say which parts of the target were examined.", "");
  }
  L.push("This report lists what was found in the units examined. It is not evidence that the rest of the code is free of vulnerabilities.");
  return L.join("\n");
}

module.exports = {
  COVERAGE_STATUSES,
  VERDICTS,
  SEVERITIES,
  ROLES,
  MIN_QUOTE_CHARS,
  MAX_SPAN,
  MAX_FIX_DISTANCE,
  normalizeDocument,
  validateDocument,
  pathSyntaxError,
  quoteLines,
  checkLocation,
  verifyFindings,
  applyFixes,
  renderReport,
  codeSpan,
  md,
};
