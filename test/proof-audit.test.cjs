"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawnSync } = require("node:child_process");

const lib = require("../skills/proof-audit/scripts/lib.cjs");
const { main } = require("../skills/proof-audit/scripts/proof-audit.cjs");

const FIX = path.join(__dirname, "fixtures");
const APP = path.join(FIX, "vulnapp");
const CLI = path.join(__dirname, "..", "skills", "proof-audit", "scripts", "proof-audit.cjs");
const load = (f) => JSON.parse(fs.readFileSync(path.join(FIX, f), "utf8"));

function run(args) {
  const out = [];
  const err = [];
  const code = main(args, { out: (s) => out.push(s), err: (s) => err.push(s) });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

const tmpdirs = [];
function tmpdir() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "proof-audit-test-"));
  tmpdirs.push(d);
  return d;
}
test.after(() => {
  for (const d of tmpdirs) fs.rmSync(d, { recursive: true, force: true });
});

/** Symlinks need extra privileges on Windows; everywhere else a failure to create one must fail CI, not skip. */
function trySymlink(t, target, link) {
  try {
    fs.symlinkSync(target, link);
    return true;
  } catch (e) {
    if (process.platform === "win32") {
      t.skip(`symlinks not permitted here (${e.code})`);
      return false;
    }
    throw e;
  }
}

function one(dir, file, line, quote, extra = {}) {
  return lib.verifyFindings([{ id: "x", verdict: "needs_validation", locations: [{ role: "sink", file, line, quote, ...extra }] }], dir, { strict: true })
    .results[0].checks[0];
}

function codesById(v) {
  return Object.fromEntries(v.results.map((r) => [r.id, r.checks.map((c) => c.code)]));
}

// --- schema --------------------------------------------------------------

test("good fixture is schema-valid", () => {
  assert.deepEqual(lib.validateDocument(load("good.json")), []);
});

test("schema rejects severity on non-confirmed, missing blocker/reason, missing quote", () => {
  const doc = {
    version: 1,
    findings: [
      { id: "a", verdict: "needs_validation", title: "t", summary: "s", severity: "high", locations: [{ role: "sink", file: "f", line: 1 }] },
      { id: "b", verdict: "rejected", title: "t", summary: "s", locations: [{ role: "sink", file: "f", line: 1, quote: "abcdefg" }] },
    ],
  };
  const errs = lib.validateDocument(doc).join("\n");
  assert.match(errs, /findings\[0\]\.severity: only confirmed/);
  assert.match(errs, /findings\[0\]\.blocker/);
  assert.match(errs, /findings\[0\]\.locations\[0\]\.quote: required/);
  assert.match(errs, /findings\[1\]\.reason/);
});

test("schema requires confirmed findings to have severity, boundary, remediation, entrypoint and sink", () => {
  const doc = {
    version: 1,
    findings: [{ id: "c", verdict: "confirmed", title: "t", summary: "s", locations: [{ role: "propagation", file: "f", line: 1, quote: "abcdefg" }] }],
  };
  const errs = lib.validateDocument(doc).join("\n");
  for (const re of [/severity/, /boundary/, /remediation/, /need an entrypoint/, /need a sink/]) assert.match(errs, re);
});

test("schema rejects duplicate ids, bad ids, bad cwe, bad version, bad end_line", () => {
  const loc = { role: "sink", file: "f", line: 5, end_line: 2, quote: "abcdefg" };
  const base = { verdict: "needs_validation", title: "t", summary: "s", blocker: "b", locations: [loc] };
  const errs = lib
    .validateDocument({ version: 2, findings: [{ id: "x", ...base, cwe: "89" }, { id: "x", ...base }, { id: "-bad", ...base }] })
    .join("\n");
  for (const re of [/\$\.version/, /duplicate id x/, /findings\[2\]\.id/, /cwe/, /end_line/]) assert.match(errs, re);
});

test("schema rejects non-object documents", () => {
  assert.ok(lib.validateDocument([]).length > 0);
  assert.ok(lib.validateDocument(null).length > 0);
  assert.ok(lib.validateDocument({ version: 1 }).length > 0);
});

test("schema checks coverage units and finding unit ids", () => {
  const errs = lib
    .validateDocument({
      version: 1,
      coverage: [
        { unit: "u1", status: "hunted" },
        { unit: "u1", status: "hunted" },
        { unit: "u2", status: "skipped" },
        { unit: "u3", status: "done" },
        { unit: "u4", status: "hunted", checked: ["", 3] },
      ],
      findings: [{ id: "x", unit: "bad unit!", verdict: "rejected", title: "t", summary: "s", reason: "r",
        locations: [{ role: "sink", file: "f", line: 1, quote: "abcdefg" }] }],
    })
    .join("\n");
  for (const re of [/duplicate unit u1/, /coverage\[2\]\.note: skipped units must say why/, /coverage\[3\]\.status/, /coverage\[4\]\.checked/, /findings\[0\]\.unit/])
    assert.match(errs, re);
  assert.match(lib.validateDocument({ version: 1, coverage: {}, findings: [] }).join(), /coverage: must be an array/);
});

// --- verification --------------------------------------------------------

test("good fixture verifies, including a multi-line quote spanning files", () => {
  const v = lib.verifyFindings(load("good.json").findings, APP);
  assert.equal(v.ok, true);
  assert.equal(v.summary.verified, 3);
  assert.equal(v.summary.location_failures, 0);
});

test("each failure class is detected with the right code", () => {
  const v = lib.verifyFindings(load("mixed.json").findings, APP);
  assert.equal(v.ok, false);
  assert.deepEqual(codesById(v), {
    "ok-one": ["OK"],
    hallucinated: ["OK", "QUOTE_NOT_FOUND"],
    drifted: ["DRIFTED"],
    "missing-file": ["FILE_MISSING"],
    escape: ["PATH_ESCAPE"],
    "too-short": ["QUOTE_TOO_SHORT"],
    "out-of-range": ["LINE_OUT_OF_RANGE"],
    ambiguous: ["AMBIGUOUS"],
    binary: ["NOT_TEXT"],
    "bad-rejected": ["FILE_MISSING"],
  });
  const drift = v.results.find((r) => r.id === "drifted").checks[0];
  assert.equal(drift.actual_line, 16);
});

test("rejected findings never gate the result", () => {
  const f = load("mixed.json").findings.filter((x) => x.id === "ok-one" || x.id === "bad-rejected");
  const v = lib.verifyFindings(f, APP);
  assert.equal(v.ok, true);
  assert.equal(v.summary.failed, 1);
  assert.equal(v.summary.gating_failed, 0);
});

test("a finding with no locations fails", () => {
  const v = lib.verifyFindings([{ id: "x", verdict: "needs_validation", locations: [] }], APP);
  assert.equal(v.ok, false);
});

test("absolute, Windows-drive, UNC and NUL paths are refused", () => {
  const getFile = () => assert.fail("must not read");
  const root = fs.realpathSync(APP);
  for (const file of [path.join(APP, "src", "server.js"), "C:\\Windows\\win.ini", "\\\\host\\share\\x", "src/server.js\0"]) {
    const c = lib.checkLocation(root, getFile, { file, line: 1, quote: "const express" });
    assert.ok(["PATH_ESCAPE", "PATH_INVALID"].includes(c.code), `${JSON.stringify(file)} -> ${c.code}`);
  }
});

test("a symlink that points outside the target is refused", (t) => {
  const dir = tmpdir();
  const outside = path.join(tmpdir(), "secret.txt");
  fs.writeFileSync(outside, "TOP SECRET VALUE\n");
  if (!trySymlink(t, outside, path.join(dir, "link.txt"))) return;
  const v = lib.verifyFindings([{ id: "s", verdict: "needs_validation", locations: [{ file: "link.txt", line: 1, quote: "TOP SECRET VALUE" }] }], dir);
  assert.equal(v.results[0].checks[0].code, "PATH_ESCAPE");
});

test("a symlink inside the target is followed", (t) => {
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, "real.js"), "const answer = 42;\n");
  if (!trySymlink(t, "real.js", path.join(dir, "alias.js"))) return;
  const v = lib.verifyFindings([{ id: "s", verdict: "needs_validation", locations: [{ file: "alias.js", line: 1, quote: "const answer = 42;" }] }], dir);
  assert.equal(v.ok, true);
});

test("directories and oversized files are refused", () => {
  const dir = tmpdir();
  fs.mkdirSync(path.join(dir, "sub"));
  fs.writeFileSync(path.join(dir, "big.txt"), Buffer.alloc(5 * 1024 * 1024 + 1, 0x61));
  const v = lib.verifyFindings(
    [
      { id: "d", verdict: "needs_validation", locations: [{ file: "sub", line: 1, quote: "anything" }] },
      { id: "b", verdict: "needs_validation", locations: [{ file: "big.txt", line: 1, quote: "aaaaaaaa" }] },
    ],
    dir,
  );
  assert.deepEqual(codesById(v), { d: ["NOT_A_FILE"], b: ["FILE_TOO_LARGE"] });
});

test("quote matching ignores indentation and whitespace runs, handles CRLF", () => {
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, "a.py"), "def f(x):\r\n    if   x:\r\n        return  os.system(x)\r\n");
  const v = lib.verifyFindings(
    [
      { id: "one", verdict: "needs_validation", locations: [{ file: "a.py", line: 3, quote: "return os.system(x)" }] },
      { id: "multi", verdict: "needs_validation", locations: [{ file: "a.py", line: 2, quote: "if x:\n  return os.system(x)" }] },
    ],
    dir,
  );
  assert.equal(v.ok, true, JSON.stringify(v.results));
});

test("a multi-line quote must be contiguous", () => {
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, "a.js"), "const a = input;\nconst b = 1;\nrun(a);\n");
  const v = lib.verifyFindings(
    [{ id: "gap", verdict: "needs_validation", locations: [{ file: "a.js", line: 1, quote: "const a = input;\nrun(a);" }] }],
    dir,
  );
  assert.equal(v.results[0].checks[0].code, "QUOTE_NOT_FOUND");
});

test("end_line widens the window a quote may sit in", () => {
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, "a.js"), "line one here\nline two here\nexec(userInput)\n");
  const at = (end_line) =>
    lib.verifyFindings([{ id: "w", verdict: "needs_validation", locations: [{ file: "a.js", line: 1, end_line, quote: "exec(userInput)" }] }], dir)
      .results[0].checks[0].code;
  assert.equal(at(3), "OK");
  assert.equal(at(undefined), "DRIFTED");
});

test("cloudflare-format findings: existence and line checks, quotes missing are warnings", () => {
  const { format, findings } = lib.normalizeDocument(load("cloudflare.json"));
  assert.equal(format, "cloudflare");
  const v = lib.verifyFindings(findings, APP);
  assert.deepEqual(codesById(v), { "sqli-users": ["QUOTE_MISSING", "QUOTE_MISSING", "QUOTE_MISSING"], ghost: ["FILE_MISSING"] });
  assert.equal(v.results[0].status, "unquoted");
  assert.equal(v.ok, false);
  const strict = lib.verifyFindings(findings, APP, { strict: true });
  assert.equal(strict.results[0].status, "failed");
});

test("applyFixes corrects uniquely drifted lines only, preserving span", () => {
  const doc = load("mixed.json");
  doc.findings.find((f) => f.id === "drifted").locations[0].end_line = 4;
  const v = lib.verifyFindings(doc.findings, APP);
  const { doc: fixed, fixed: n } = lib.applyFixes(doc, v);
  assert.equal(n, 1);
  const loc = fixed.findings.find((f) => f.id === "drifted").locations[0];
  assert.deepEqual([loc.line, loc.end_line], [16, 17]);
  assert.equal(fixed.findings.find((f) => f.id === "ambiguous").locations[0].line, 1);
  assert.equal(doc.findings.find((f) => f.id === "drifted").locations[0].line, 3, "input not mutated");
});

// --- report --------------------------------------------------------------

test("report includes verified findings and excludes failed ones", () => {
  const doc = load("good.json");
  doc.findings.push({
    id: "fake-rce",
    verdict: "confirmed",
    title: "Invented RCE",
    summary: "s",
    severity: "critical",
    boundary: { attacker: "a", asset: "b" },
    remediation: "r",
    locations: [
      { role: "entrypoint", file: "src/server.js", line: 9, quote: "const name = req.query.name;" },
      { role: "sink", file: "src/server.js", line: 10, quote: "child_process.exec(name)" },
    ],
  });
  assert.deepEqual(lib.validateDocument(doc), []);
  const md = lib.renderReport(doc, lib.verifyFindings(doc.findings, APP, { strict: true }));
  assert.match(md, /### sqli-users-name: SQL injection/);
  assert.match(md, /\*\*Severity:\*\* critical \| \*\*CWE-89\*\*/);
  assert.match(md, /## Needs validation[\s\S]*path-traversal-files/);
  assert.match(md, /## Excluded: citation failures[\s\S]*fake-rce: Invented RCE \(`src\/server.js:10` QUOTE_NOT_FOUND\)/);
  assert.doesNotMatch(md, /### fake-rce/);
  assert.match(md, /## Rejected candidates[\s\S]*health-info-leak/);
  assert.match(md, /\| 1 \(1 critical\) \| 1 \| 1 \| 1 \|/);
  assert.match(md, /## Coverage\n\n3 planned units: 2 hunted, 1 skipped, 0 out of scope\./);
  assert.match(md, /\| u01-http-injection \| hunted \| sqli-users-name, path-traversal-files \| GET \/users; GET \/files\/:name \|/);
  assert.match(md, /\| u03-deps \| skipped \| - \| no lockfile in repo \|/);
});

test("report says plainly when no coverage plan was recorded", () => {
  const doc = load("good.json");
  delete doc.coverage;
  const md = lib.renderReport(doc, lib.verifyFindings(doc.findings, APP));
  assert.match(md, /No coverage plan was recorded/);
  assert.match(md, /not evidence that the rest of the code is free of vulnerabilities/);
});

test("report escapes markdown in titles and fences quotes containing backticks", () => {
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, "a.md"), "run ```danger``` now\n");
  const doc = {
    version: 1,
    findings: [{ id: "x", verdict: "needs_validation", title: "<img src=x onerror=alert(1)>", summary: "s", blocker: "b",
      locations: [{ role: "sink", file: "a.md", line: 1, quote: "run ```danger``` now" }] }],
  };
  const md = lib.renderReport(doc, lib.verifyFindings(doc.findings, dir));
  assert.match(md, /\\<img src=x onerror=alert\(1\)\\>/);
  assert.match(md, /  ````\n  run ```danger``` now\n  ````/);
});

// --- CLI -----------------------------------------------------------------

test("cli: validate, verify, report exit codes", () => {
  const good = path.join(FIX, "good.json");
  const mixed = path.join(FIX, "mixed.json");
  assert.equal(run(["validate", good]).code, 0);
  assert.equal(run(["validate", mixed]).code, 1, "validate also enforces path and quote-length rules");
  assert.equal(run(["verify", good, "--target", APP]).code, 0);
  const bad = run(["verify", mixed, "--target", APP]);
  assert.equal(bad.code, 1);
  assert.match(bad.out, /FAIL  hallucinated/);
  assert.match(bad.out, /QUOTE_NOT_FOUND/);
  const json = JSON.parse(run(["verify", mixed, "--target", APP, "--json"]).out);
  assert.equal(json.format, "native");
  assert.equal(json.ok, false);
  assert.equal(run(["verify", path.join(FIX, "cloudflare.json"), "--target", APP]).code, 1);
});

test("cli: report writes a file", () => {
  const out = path.join(tmpdir(), "nested", "REPORT.md");
  const r = run(["report", path.join(FIX, "good.json"), "--target", APP, "--out", out]);
  assert.equal(r.code, 0, r.err);
  assert.match(fs.readFileSync(out, "utf8"), /# Security audit report/);
});

test("cli: report refuses schema-invalid input", () => {
  const f = path.join(tmpdir(), "bad.json");
  fs.writeFileSync(f, JSON.stringify({ version: 1, findings: [{ id: "x", verdict: "confirmed" }] }));
  assert.equal(run(["report", f, "--target", APP]).code, 1);
});

test("cli: --fix writes corrected copy and re-verifies", () => {
  const dir = tmpdir();
  const src = path.join(dir, "in.json");
  const doc = load("mixed.json");
  doc.findings = doc.findings.filter((f) => f.id === "drifted" || f.id === "ok-one");
  fs.writeFileSync(src, JSON.stringify(doc));
  const out = path.join(dir, "out.json");
  const r = run(["verify", src, "--target", APP, "--fix", "--out", out]);
  assert.equal(r.code, 0, r.err);
  assert.match(r.err, /fixed 1 drifted/);
  assert.equal(JSON.parse(fs.readFileSync(out, "utf8")).findings[1].locations[0].line, 16);
  assert.equal(JSON.parse(fs.readFileSync(src, "utf8")).findings[1].locations[0].line, 3, "input untouched");
});

test("cli: usage errors exit 2", () => {
  assert.equal(run([]).code, 2);
  assert.equal(run(["--help"]).code, 0);
  assert.equal(run(["bogus", "x.json"]).code, 2);
  assert.equal(run(["verify", path.join(FIX, "good.json")]).code, 2);
  assert.equal(run(["verify", path.join(FIX, "good.json"), "--target", "/definitely/not/here"]).code, 2);
  assert.equal(run(["verify", path.join(FIX, "good.json"), "--target", APP, "--wat"]).code, 2);
  assert.equal(run(["validate", "/no/such/file.json"]).code, 2);
  assert.equal(run(["verify", path.join(FIX, "cloudflare.json"), "--target", APP, "--fix", "--out", "x"]).code, 2);
  const notJson = path.join(tmpdir(), "x.json");
  fs.writeFileSync(notJson, "{nope");
  assert.equal(run(["validate", notJson]).code, 2);
  fs.writeFileSync(notJson, '"a string"');
  assert.equal(run(["verify", notJson, "--target", APP]).code, 2);
});

test("cli: warns when source_ref differs from the target's git HEAD", (t) => {
  try {
    execFileSync("git", ["--version"], { stdio: "ignore" });
  } catch {
    t.skip("git not installed");
    return;
  }
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, "a.js"), "eval(location.hash)\n");
  const git = (...a) => execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", ...a], { stdio: "ignore" });
  git("init", "-q");
  git("add", ".");
  git("commit", "-qm", "x");
  const f = path.join(dir, "f.json");
  const doc = { version: 1, target: { source_ref: "0123456789abcdef" },
    findings: [{ id: "x", verdict: "needs_validation", title: "t", summary: "s", blocker: "b", locations: [{ role: "sink", file: "a.js", line: 1, quote: "eval(location.hash)" }] }] };
  fs.writeFileSync(f, JSON.stringify(doc));
  assert.match(run(["verify", f, "--target", dir]).out, /warning: findings were written for 0123456789abcdef/);
  doc.target.source_ref = execFileSync("git", ["-C", dir, "rev-parse", "--short", "HEAD"], { encoding: "utf8" }).trim();
  fs.writeFileSync(f, JSON.stringify(doc));
  assert.doesNotMatch(run(["verify", f, "--target", dir]).out, /warning/);
});

test("cli: notes when source_ref cannot be checked because the target is not a git checkout", () => {
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, "a.js"), "eval(location.hash)\n");
  const f = path.join(dir, "f.json");
  fs.writeFileSync(f, JSON.stringify({ version: 1, target: { source_ref: "abc1234" },
    findings: [{ id: "x", verdict: "needs_validation", title: "t", summary: "s", blocker: "b", locations: [{ role: "sink", file: "a.js", line: 1, quote: "eval(location.hash)" }] }] }));
  const r = run(["verify", f, "--target", dir]);
  assert.equal(r.code, 0);
  assert.match(r.out, /not the root of a git checkout/);
});

test("cli: runs as a real process with correct exit code", () => {
  const ok = spawnSync(process.execPath, [CLI, "verify", path.join(FIX, "good.json"), "--target", APP], { encoding: "utf8" });
  assert.equal(ok.status, 0, ok.stderr);
  const bad = spawnSync(process.execPath, [CLI, "verify", path.join(FIX, "mixed.json"), "--target", APP], { encoding: "utf8" });
  assert.equal(bad.status, 1);
});

// --- hardening (from pre-publication review) --------------------------------

test("end_line cannot widen the window past MAX_SPAN or past end of file", () => {
  const dir = tmpdir();
  const lines = Array.from({ length: 80 }, (_, i) => `const v${i} = ${i};`);
  lines[70] = "spawn(cmd, { shell: true });";
  fs.writeFileSync(path.join(dir, "a.js"), lines.join("\n") + "\n");
  assert.equal(one(dir, "a.js", 1, "spawn(cmd, { shell: true });", { end_line: 999999 }).code, "LINE_OUT_OF_RANGE");
  assert.equal(one(dir, "a.js", 1, "spawn(cmd, { shell: true });", { end_line: 75 }).code, "LINE_OUT_OF_RANGE");
  assert.equal(one(dir, "a.js", 60, "spawn(cmd, { shell: true });", { end_line: 75 }).code, "OK");
  const errs = lib.validateDocument({ version: 1, findings: [{ id: "x", verdict: "needs_validation", title: "t", summary: "s", blocker: "b",
    locations: [{ role: "sink", file: "a.js", line: 1, end_line: 999, quote: "spawn(cmd)" }] }] }).join();
  assert.match(errs, /end_line: may be at most 50/);
});

test("comment markers inside strings do not let a quote skip code", () => {
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, "a.js"), 'const msg = "see #docs"; runShell(userCmd);\nnext();\nlet x = 1; // note\nrun(x);\n');
  assert.equal(one(dir, "a.js", 1, 'const msg = "see\nnext();').code, "QUOTE_NOT_FOUND");
  assert.equal(one(dir, "a.js", 3, "let x = 1;\nrun(x);").code, "OK");
});

test("identifier boundaries include non-ASCII letters", () => {
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, "a.js"), "réexec(cmd);\n");
  assert.equal(one(dir, "a.js", 1, "exec(cmd);").code, "QUOTE_NOT_FOUND");
});

test("quotes must not cut identifiers in half", () => {
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, "a.js"), "const out = safe_exec(cmd, { shell: false });\nrun(evaluate(x));\nexec(cmd);\n");
  assert.equal(one(dir, "a.js", 1, "exec(cmd, { shell").code, "QUOTE_NOT_FOUND");
  assert.equal(one(dir, "a.js", 2, "eval(x));").code, "QUOTE_NOT_FOUND");
  assert.equal(one(dir, "a.js", 1, "safe_exec(cmd, { shell").code, "OK");
  assert.equal(one(dir, "a.js", 3, "exec(cmd);").code, "OK");
  fs.writeFileSync(path.join(dir, "b.js"), "const userInputValue = trusted;\n");
  assert.equal(one(dir, "b.js", 1, "const userInput").code, "QUOTE_NOT_FOUND");
  assert.equal(one(dir, "a.js", 1, "= safe_exec(cmd").code, "OK", "punctuation at the edge needs no boundary");
});

test("a multi-line quote may leave out a trailing comment on its first line", () => {
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, "a.js"), "if (isAdmin(req.user)) { // only admins\n    db.exec(req.body.sql);\n}\n");
  assert.equal(one(dir, "a.js", 1, "if (isAdmin(req.user)) {\n    db.exec(req.body.sql);").code, "OK");
  assert.equal(one(dir, "a.js", 1, "isAdmin(req.user)) { // only admins\n db.exec(req.body.sql);").code, "OK");
  assert.equal(one(dir, "a.js", 1, "if (isAdmin(req.user)) {\n    db.exec(req.body.sql); // added").code, "QUOTE_NOT_FOUND");
});

test("far drift is DRIFTED_FAR and not auto-fixed; a consistent shift is fixed", () => {
  const dir = tmpdir();
  const lines = Array.from({ length: 120 }, (_, i) => `const filler${i} = ${i};`);
  lines[99] = "res.json(rows);";
  lines[109] = "db.query(sql);";
  fs.writeFileSync(path.join(dir, "a.js"), lines.join("\n") + "\n");
  const far = { version: 1, findings: [{ id: "f", verdict: "needs_validation", title: "t", summary: "s", blocker: "b",
    locations: [{ role: "sink", file: "a.js", line: 5, quote: "res.json(rows);" }] }] };
  const v1 = lib.verifyFindings(far.findings, dir, { strict: true });
  assert.equal(v1.results[0].checks[0].code, "DRIFTED_FAR");
  assert.equal(lib.applyFixes(far, v1).fixed, 0);
  const shifted = { version: 1, findings: [{ id: "g", verdict: "needs_validation", title: "t", summary: "s", blocker: "b",
    locations: [{ role: "sink", file: "a.js", line: 40, quote: "res.json(rows);" }, { role: "sink", file: "a.js", line: 50, quote: "db.query(sql);" }] }] };
  const v2 = lib.verifyFindings(shifted.findings, dir, { strict: true });
  assert.deepEqual(v2.results[0].checks.map((c) => c.code), ["DRIFTED", "DRIFTED"]);
  const { doc, fixed } = lib.applyFixes(shifted, v2);
  assert.equal(fixed, 2);
  assert.deepEqual(doc.findings[0].locations.map((l) => l.line), [100, 110]);
});

test("verify schema-checks native files and requires quotes", () => {
  const dir = tmpdir();
  const f = path.join(dir, "f.json");
  const write = (o) => fs.writeFileSync(f, typeof o === "string" ? o : JSON.stringify(o));
  write({ version: 99, findings: [] });
  assert.equal(run(["verify", f, "--target", APP]).code, 1);
  write({ version: 1, findings: [null] });
  assert.equal(run(["verify", f, "--target", APP]).code, 1);
  write({ version: 1, findings: [{ id: "x", verdict: "bogus", title: "t", summary: "s", locations: [] }] });
  assert.equal(run(["verify", f, "--target", APP]).code, 1);
  write({ version: 1, findings: [{ id: "x", verdict: "needs_validation", title: "t", summary: "s", blocker: "b",
    locations: [{ role: "sink", file: "src/server.js", line: 9 }] }] });
  const r = run(["verify", f, "--target", APP]);
  assert.equal(r.code, 1);
  assert.match(r.out, /QUOTE_MISSING/);
  write([false, null]);
  assert.equal(run(["verify", f, "--target", APP]).code, 1, "non-object Cloudflare records gate");
  write("\uFEFF" + JSON.stringify({ version: 1, findings: [] }));
  assert.equal(run(["verify", f, "--target", APP]).code, 0, "UTF-8 BOM is accepted");
});

test("malformed input never crashes with an internal error", () => {
  const dir = tmpdir();
  const f = path.join(dir, "f.json");
  const cases = [
    [{ trace: [null], evidence: [null, 3, "x"] }],
    [{ trace: "nope", evidence: {} }],
    [[1, 2]],
    { version: 1, target: { source_ref: 5 }, findings: [] },
    { version: 1, target: { source_ref: ["a"] }, findings: [] },
    { version: 1, target: null, findings: [{}] },
    { version: 1, findings: [{ id: "x", verdict: "rejected", title: "t", summary: "s", reason: "r", locations: [null, 4, { file: 7, line: "x", quote: {} }] }] },
  ];
  for (const c of cases) {
    fs.writeFileSync(f, JSON.stringify(c));
    for (const cmd of [["validate", f], ["verify", f, "--target", APP], ["report", f, "--target", APP]]) {
      const r = run(cmd);
      assert.ok([0, 1, 2].includes(r.code), `${JSON.stringify(c)} ${cmd[0]} -> ${r.code}: ${r.err}`);
      assert.doesNotMatch(r.err, /internal/);
    }
  }
});

test("deeply nested JSON is a usage error, not a crash", () => {
  const f = path.join(tmpdir(), "deep.json");
  fs.writeFileSync(f, '{"version":1,"x":' + "[".repeat(5000) + "]".repeat(5000) + ',"findings":[]}');
  for (const cmd of [["validate", f], ["verify", f, "--target", APP, "--fix", "--out", f + ".out"]]) {
    const r = run(cmd);
    assert.equal(r.code, 2, r.err);
    assert.match(r.err, /nested more than 64 levels/);
  }
});

test("source_ref check never runs repository-configured filters", (t) => {
  try {
    execFileSync("git", ["--version"], { stdio: "ignore" });
  } catch {
    t.skip("git not installed");
    return;
  }
  if (process.platform === "win32") {
    t.skip("filter command uses sh");
    return;
  }
  const dir = tmpdir();
  const marker = path.join(dir, "PWNED");
  fs.writeFileSync(path.join(dir, "a.js"), "eval(location.hash)\n");
  const g = (...a) => execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", ...a], { encoding: "utf8" });
  g("init", "-q");
  g("add", ".");
  g("commit", "-qm", "x");
  fs.writeFileSync(path.join(dir, ".git", "info", "attributes"), "*.js filter=pw\n");
  g("config", "filter.pw.clean", `sh -c 'touch "${marker}"; cat'`);
  const old = new Date("2004-01-01");
  fs.utimesSync(path.join(dir, "a.js"), old, old);
  const f = path.join(tmpdir(), "f.json");
  fs.writeFileSync(f, JSON.stringify({ version: 1, target: { source_ref: g("rev-parse", "HEAD").trim() },
    findings: [{ id: "x", verdict: "needs_validation", title: "t", summary: "s", blocker: "b", locations: [{ role: "sink", file: "a.js", line: 1, quote: "eval(location.hash)" }] }] }));
  run(["verify", f, "--target", dir]);
  run(["report", f, "--target", dir]);
  assert.equal(fs.existsSync(marker), false, "a git filter from the target ran");
});

test("cli: write failures, same-file --fix, stray --out, option parsing", () => {
  const good = path.join(FIX, "good.json");
  assert.equal(run(["report", good, "--target", APP, "--out", path.join(good, "x.md")]).code, 2);
  const dir = tmpdir();
  const copy = path.join(dir, "c.json");
  fs.copyFileSync(good, copy);
  const before = fs.readFileSync(copy, "utf8");
  assert.equal(run(["verify", copy, "--target", APP, "--fix", "--out", copy]).code, 2);
  assert.equal(fs.readFileSync(copy, "utf8"), before);
  assert.equal(run(["verify", good, "--target", APP, "--out", path.join(dir, "o.json")]).code, 2);
  assert.equal(run(["verify", good, "--target", "--strict"]).code, 2);
  assert.equal(run(["verify", good, `--target=${APP}`]).code, 0);
  assert.equal(run(["validate", good, "--target", APP]).code, 2);
  assert.equal(run(["verify", good, "--target", APP, "--strict=yes"]).code, 2);
});

test("cli: report exits 1 when findings were excluded, but still writes the report", () => {
  const dir = tmpdir();
  const doc = load("good.json");
  doc.findings[1].locations[0].quote = "path.join(DOWNLOADS, req.params.name)";
  const f = path.join(dir, "f.json");
  fs.writeFileSync(f, JSON.stringify(doc));
  const out = path.join(dir, "R.md");
  const r = run(["report", f, "--target", APP, "--out", out]);
  assert.equal(r.code, 1);
  assert.match(fs.readFileSync(out, "utf8"), /## Excluded: citation failures/);
});

test("report: paths and refs in code spans are not backslash-escaped; backticks are safe", () => {
  const dir = tmpdir();
  fs.mkdirSync(path.join(dir, "my_dir"));
  fs.writeFileSync(path.join(dir, "my_dir", "user_model.js"), "const user_name = req.body.user_name;\n");
  const doc = { version: 1, target: { name: "t", source_ref: "abc_def" },
    findings: [{ id: "x", verdict: "needs_validation", title: "t", summary: "s", blocker: "b",
      locations: [{ role: "sink", file: "my_dir/user_model.js", line: 1, quote: "req.body.user_name" }] }] };
  const md = lib.renderReport(doc, lib.verifyFindings(doc.findings, dir, { strict: true }));
  assert.match(md, /`my_dir\/user_model.js:1`/);
  assert.match(md, /at `abc_def`/);
  assert.equal(lib.codeSpan("we`ird.js"), "``we`ird.js``");
  assert.equal(lib.codeSpan("`x"), "`` `x ``");
});

test("report: prose cannot inject headings, list items or extra lines", () => {
  assert.equal(lib.md("# Fake heading"), "\\# Fake heading");
  assert.equal(lib.md("Title\rInjected"), "Title Injected");
  assert.equal(lib.md("a\u2028b"), "a b");
  assert.equal(lib.md("- item"), "\\- item");
  assert.equal(lib.md("1. item"), "1\\. item");
  assert.equal(lib.md("    indented code?"), "indented code?");
  assert.equal(lib.md("> quote"), "\\> quote");
});

test("cli: terminal output neutralizes control characters in untrusted fields", () => {
  const dir = tmpdir();
  const f = path.join(dir, "f.json");
  fs.writeFileSync(f, JSON.stringify({ version: 1, findings: [{ id: "x", verdict: "needs_validation", title: "evil\u001b[2K\rPASS", summary: "s", blocker: "b",
    locations: [{ role: "sink", file: "src/nope.js", line: 1, quote: "nothing here" }] }] }));
  const r = run(["verify", f, "--target", APP]);
  assert.doesNotMatch(r.out, /[\u001b\r]/);
  assert.match(r.out, /evil\\u001b\[2K\\u000dPASS/);
});

test("path rules: backslashes, case mismatches, trailing slash or dot are refused; ..name files are fine", () => {
  const dir = tmpdir();
  fs.mkdirSync(path.join(dir, "src"));
  fs.writeFileSync(path.join(dir, "src", "server.js"), "app.listen(port);\n");
  fs.writeFileSync(path.join(dir, "..foo.js"), "app.listen(port);\n");
  const q = "app.listen(port);";
  assert.equal(one(dir, "src\\server.js", 1, q).code, "PATH_INVALID");
  assert.equal(one(dir, "SRC/SERVER.JS", 1, q).code, "FILE_MISSING");
  assert.equal(one(dir, "src/server.js/", 1, q).code, "PATH_INVALID");
  assert.equal(one(dir, "src/server.js.", 1, q).code, "PATH_INVALID");
  assert.equal(one(dir, "src/server.js ", 1, q).code, "PATH_INVALID");
  assert.equal(one(dir, "./src/server.js", 1, q).code, "OK", "one leading ./ is tolerated");
  assert.equal(one(dir, "././src/server.js", 1, q).code, "PATH_INVALID");
  assert.equal(one(dir, ".", 1, q).code, "PATH_INVALID");
  assert.equal(one(dir, "src/server.js\u0000", 1, q).code, "PATH_INVALID");
  assert.equal(one(dir, "..foo.js", 1, q).code, "OK");
  assert.equal(one(dir, "src/server.js", 1, q).code, "OK");
  assert.match(lib.validateDocument({ version: 1, findings: [{ id: "x", verdict: "needs_validation", title: "t", summary: "s", blocker: "b",
    locations: [{ role: "sink", file: "C:\\x\\..\\y", line: 1, quote: "});" }] }] }).join(), /absolute paths[\s\S]*6 non-space/);
});

test("cli: source_ref checks are case-insensitive, need 7+ hex chars, and flag dirty trees", (t) => {
  try {
    execFileSync("git", ["--version"], { stdio: "ignore" });
  } catch {
    t.skip("git not installed");
    return;
  }
  const dir = tmpdir();
  fs.writeFileSync(path.join(dir, "a.js"), "eval(location.hash)\n");
  const g = (...a) => execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", ...a], { encoding: "utf8" });
  g("init", "-q");
  g("add", ".");
  g("commit", "-qm", "x");
  const head = g("rev-parse", "HEAD").trim();
  const f = path.join(tmpdir(), "f.json");
  const doc = (ref) => ({ version: 1, target: { source_ref: ref },
    findings: [{ id: "x", verdict: "needs_validation", title: "t", summary: "s", blocker: "b", locations: [{ role: "sink", file: "a.js", line: 1, quote: "eval(location.hash)" }] }] });
  const outFor = (ref) => {
    fs.writeFileSync(f, JSON.stringify(doc(ref)));
    return run(["verify", f, "--target", dir]).out;
  };
  assert.doesNotMatch(outFor(head.slice(0, 10).toUpperCase()), /warning/);
  assert.match(outFor(head.slice(0, 1)), /not a 7-40 character commit hash/);
  const rel = path.relative(process.cwd(), dir);
  fs.writeFileSync(f, JSON.stringify(doc(head.slice(0, 7))));
  assert.doesNotMatch(run(["verify", f, "--target", rel]).out, /warning/, "relative --target works");
  const sub = path.join(dir, "sub");
  fs.mkdirSync(sub);
  fs.writeFileSync(path.join(sub, "a.js"), "eval(location.hash)\n");
  fs.writeFileSync(f, JSON.stringify(doc(head)));
  assert.match(run(["verify", f, "--target", sub]).out, /not the root of a git checkout/);
});
