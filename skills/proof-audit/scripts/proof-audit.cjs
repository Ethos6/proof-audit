#!/usr/bin/env node
"use strict";
// proof-audit CLI. Zero dependencies; Node >= 18.
//
//   proof-audit validate <findings.json>
//   proof-audit verify   <findings.json> --target <repo> [--strict] [--json] [--fix --out <file>]
//   proof-audit report   <findings.json> --target <repo> [--out REPORT.md]
//
// Exit codes: 0 ok; 1 findings invalid, citations failed, or (report) findings excluded;
// 2 usage or I/O error; 3 internal error.

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const lib = require("./lib.cjs");

const USAGE = `Usage:
  proof-audit validate <findings.json>
  proof-audit verify   <findings.json> --target <repo> [--strict] [--json] [--fix --out <file>]
  proof-audit report   <findings.json> --target <repo> [--out <REPORT.md>]

validate  Check a native proof-audit findings file against the schema.
verify    Check every cited file, line and quote against the target source tree.
          Native files are schema-checked first and must quote every location.
          Also accepts Cloudflare security-audit-skill findings.json (file/line
          only; missing quotes are warnings unless --strict).
          --fix writes a copy with nearby drifted line numbers corrected.
report    Validate, verify, then render a Markdown report that includes only
          findings whose citations verified. Exits 1 if any were excluded.

Exit codes: 0 ok, 1 invalid/failed/excluded, 2 usage or I/O error, 3 internal error.`;

class UsageError extends Error {}

const VALUE_OPTS = new Set(["target", "out"]);
const FLAG_OPTS = new Set(["strict", "json", "fix", "help"]);

function parseArgs(argv) {
  const out = { _: [], flags: new Set(), opts: {} };
  for (let i = 0; i < argv.length; i++) {
    let a = argv[i];
    if (a === "-h") a = "--help";
    if (!a.startsWith("--") || a === "--") {
      if (a.startsWith("-") && a !== "-") throw new UsageError(`unknown option ${a}`);
      out._.push(a);
      continue;
    }
    const eq = a.indexOf("=");
    const name = a.slice(2, eq === -1 ? undefined : eq);
    if (VALUE_OPTS.has(name)) {
      let v;
      if (eq !== -1) v = a.slice(eq + 1);
      else {
        v = argv[++i];
        if (v === undefined || v.startsWith("--")) throw new UsageError(`--${name} needs a value`);
      }
      if (v === "") throw new UsageError(`--${name} needs a value`);
      out.opts[name] = v;
    } else if (FLAG_OPTS.has(name) && eq === -1) out.flags.add(name);
    else throw new UsageError(`unknown option ${a}`);
  }
  return out;
}

/** Reject absurdly deep JSON so later JSON.stringify/recursion cannot overflow the stack. */
function checkDepth(value, max = 64) {
  const stack = [[value, 1]];
  while (stack.length) {
    const [v, d] = stack.pop();
    if (v === null || typeof v !== "object") continue;
    if (d > max) return false;
    for (const k of Object.keys(v)) stack.push([v[k], d + 1]);
  }
  return true;
}

function readJson(file) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (e) {
    throw new UsageError(`cannot read ${file}: ${e.code || e.message}`);
  }
  let value;
  try {
    value = JSON.parse(text.replace(/^\uFEFF/, ""));
  } catch (e) {
    throw new UsageError(`${file} is not valid JSON: ${e.message}`);
  }
  if (!checkDepth(value)) throw new UsageError(`${file} is nested more than 64 levels deep`);
  return value;
}

function writeFile(file, text) {
  try {
    fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
    fs.writeFileSync(file, text);
  } catch (e) {
    throw new UsageError(`cannot write ${file}: ${e.code || e.message}`);
  }
}

function sameFile(a, b) {
  const real = (p) => {
    try {
      return fs.realpathSync(p);
    } catch {
      return path.resolve(p);
    }
  };
  return real(a) === real(b);
}

function requireTarget(args) {
  const t = args.opts.target;
  if (!t) throw new UsageError("--target <repo> is required");
  let st;
  try {
    st = fs.statSync(t);
  } catch {
    throw new UsageError(`target ${t} does not exist`);
  }
  if (!st.isDirectory()) throw new UsageError(`target ${t} is not a directory`);
  return t;
}

/** Find git on PATH explicitly, so a git(.exe) inside an untrusted working directory is never run. */
function findGit() {
  const names = process.platform === "win32" ? ["git.exe"] : ["git"];
  for (const dir of (process.env.PATH || "").split(path.delimiter)) {
    if (!dir || !path.isAbsolute(dir)) continue;
    for (const n of names) {
      const p = path.join(dir, n);
      try {
        if (fs.statSync(p).isFile()) return p;
      } catch {
        /* keep looking */
      }
    }
  }
  return null;
}

/**
 * Run a read-only git plumbing command against the target. Only rev-parse is used:
 * commands that read the worktree (status, diff) can run filters or fsmonitor hooks
 * configured inside an untrusted repository.
 */
function git(gitPath, dir, args) {
  try {
    return execFileSync(gitPath, ["-c", "core.fsmonitor=false", "-C", path.resolve(dir), ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      cwd: os.tmpdir(),
      timeout: 10000,
    }).trim();
  } catch {
    return null;
  }
}

function sourceRefWarnings(doc, target) {
  const ref = doc && !Array.isArray(doc) && doc.target && typeof doc.target === "object" ? doc.target.source_ref : undefined;
  if (ref === undefined || ref === null) return [];
  if (typeof ref !== "string" || !/^[0-9a-fA-F]{7,40}$/.test(ref))
    return [`source_ref ${JSON.stringify(ref)} is not a 7-40 character commit hash, so it was not checked`];
  const gitPath = findGit();
  // --show-prefix is empty exactly when the target is the top of a work tree. Asking git
  // avoids comparing paths, which differ in form on Windows (slashes, 8.3 short names).
  const prefix = gitPath ? git(gitPath, target, ["rev-parse", "--show-prefix"]) : null;
  const head = prefix === "" ? git(gitPath, target, ["rev-parse", "HEAD"]) : null;
  if (!head)
    return [`findings record source_ref ${ref}, but the target is not the root of a git checkout (or git is unavailable), so the ref was not checked`];
  const out = [];
  if (!head.toLowerCase().startsWith(ref.toLowerCase()))
    out.push(`findings were written for ${ref} but the target is at ${head.slice(0, 12)}; line numbers may have moved`);
  return out;
}

/** Make untrusted strings safe to print on a terminal (no ANSI, CR, or other control/bidi characters). */
function safe(s) {
  return String(s ?? "").replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, (c) =>
    "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}

function printVerification(v, warnings, log) {
  for (const w of warnings) log(`warning: ${safe(w)}`);
  for (const r of v.results) {
    const mark = r.status === "verified" ? "PASS" : r.status === "unquoted" ? "WARN" : r.gating ? "FAIL" : "info";
    log(`${mark}  ${safe(r.id)} [${safe(r.verdict)}] ${safe(r.title)}`.trimEnd());
    for (const c of r.checks) {
      if (c.status === "ok") continue;
      log(`      ${c.status === "fail" ? "x" : "!"} ${safe(c.file)}:${safe(c.line)} ${c.code}${c.detail ? ` - ${safe(c.detail)}` : ""}`);
    }
    if (r.checks.length === 0) log("      x no locations cited (or not a finding object)");
  }
  const s = v.summary;
  log("");
  log(`${s.findings} findings (${s.verified} verified, ${s.unquoted} unquoted, ${s.failed} failed), ${s.locations} locations checked` +
    (s.failed !== s.gating_failed ? ` (${s.failed - s.gating_failed} failed finding(s) are rejected ones, which do not gate)` : ""));
  if (!v.ok) log(`result: ${s.gating_failed} finding(s) cite source that does not match`);
  else if (s.unquoted) log(`result: no failures, but ${s.unquoted} finding(s) have no quotes, so only file and line were checked (use --strict to require quotes)`);
  else log("result: citations OK");
}

function reportSchemaErrors(errors, file, io) {
  for (const e of errors) io.err(`invalid: ${safe(e)}`);
  io.err(`${errors.length} schema error(s) in ${file}`);
}

function main(argv, io = { out: (s) => process.stdout.write(s + "\n"), err: (s) => process.stderr.write(s + "\n") }) {
  try {
    const args = parseArgs(argv);
    if (args.flags.has("help")) {
      io.out(USAGE);
      return 0;
    }
    if (args._.length === 0) {
      io.err(USAGE);
      return 2;
    }
    const [cmd, file, ...rest] = args._;
    if (!["validate", "verify", "report"].includes(cmd)) throw new UsageError(`unknown command ${cmd}`);
    if (rest.length) throw new UsageError(`unexpected argument ${rest[0]}`);
    if (!file) throw new UsageError(`${cmd} needs a findings file`);
    const allowed = { validate: [], verify: ["target", "strict", "json", "fix", "out"], report: ["target", "out"] }[cmd];
    for (const k of [...args.flags, ...Object.keys(args.opts)]) if (!allowed.includes(k)) throw new UsageError(`--${k} is not valid for ${cmd}`);

    if (cmd === "validate") {
      const doc = readJson(file);
      const errors = lib.validateDocument(doc);
      if (errors.length) {
        reportSchemaErrors(errors, file, io);
        return 1;
      }
      io.out(`valid: ${file} (${doc.findings.length} findings)`);
      return 0;
    }

    if (cmd === "verify") {
      const target = requireTarget(args);
      const fix = args.flags.has("fix");
      if (args.opts.out && !fix) throw new UsageError("--out is only used with --fix");
      if (fix && !args.opts.out) throw new UsageError("--fix needs --out <file> (the input is never overwritten)");
      if (fix && sameFile(file, args.opts.out)) throw new UsageError("--out must be a different file from the input");
      const raw = readJson(file);
      let norm;
      try {
        norm = lib.normalizeDocument(raw);
      } catch (e) {
        throw new UsageError(e.message);
      }
      const { format, doc, findings } = norm;
      if (fix && format !== "native") throw new UsageError("--fix only supports native proof-audit files");
      if (format === "native") {
        const errors = lib.validateDocument(raw, { citations: false });
        if (errors.length) {
          reportSchemaErrors(errors, file, io);
          io.err("fix the schema errors (run validate) before verifying citations");
          return 1;
        }
      }
      // Native files must quote every location; --strict extends that to Cloudflare files.
      const strict = format === "native" || args.flags.has("strict");
      const v = lib.verifyFindings(findings, target, { strict });
      const warnings = sourceRefWarnings(raw, target);
      if (args.flags.has("json")) io.out(JSON.stringify({ format, warnings, ...v }, null, 2));
      else printVerification(v, warnings, io.out);
      if (fix) {
        const { doc: fixedDoc, fixed } = lib.applyFixes(doc, v);
        writeFile(args.opts.out, JSON.stringify(fixedDoc, null, 2) + "\n");
        const again = lib.verifyFindings(fixedDoc.findings, target, { strict });
        io.err(`fixed ${fixed} drifted line number(s); wrote ${args.opts.out}; re-check: ${again.ok ? "citations OK" : "still failing"}`);
        return again.ok ? 0 : 1;
      }
      return v.ok ? 0 : 1;
    }

    // report
    const target = requireTarget(args);
    const doc = readJson(file);
    const errors = lib.validateDocument(doc);
    if (errors.length) {
      reportSchemaErrors(errors, file, io);
      io.err("fix the schema errors before rendering a report");
      return 1;
    }
    const v = lib.verifyFindings(doc.findings, target, { strict: true });
    for (const w of sourceRefWarnings(doc, target)) io.err(`warning: ${safe(w)}`);
    const text = lib.renderReport(doc, v);
    if (args.opts.out) {
      writeFile(args.opts.out, text + "\n");
      io.err(`wrote ${args.opts.out} (${v.summary.verified} verified, ${v.summary.gating_failed} excluded)`);
    } else io.out(text);
    if (!v.ok) io.err(`${v.summary.gating_failed} finding(s) excluded because their citations failed; run verify for details`);
    return v.ok ? 0 : 1;
  } catch (e) {
    if (e instanceof UsageError) {
      io.err(`error: ${safe(e.message)}`);
      return 2;
    }
    io.err(`error: internal: ${String(e && e.stack ? e.stack : e).split("\n").map(safe).join("\n")}`);
    return 3;
  }
}

module.exports = { main };
if (require.main === module) {
  // Exit quietly when piped into a pager or `head` that closes early.
  for (const stream of [process.stdout, process.stderr]) stream.on("error", (e) => (e.code === "EPIPE" ? process.exit(process.exitCode ?? 0) : (() => { throw e; })()));
  process.exitCode = main(process.argv.slice(2));
}
