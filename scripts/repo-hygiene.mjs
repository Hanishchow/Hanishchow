#!/usr/bin/env node
// repo-hygiene.mjs — audits the GitHub account for the boring 10%:
// leaked secret files, bare descriptions, missing topics, and the search-visibility
// assets that silently stop working if a file gets deleted.
//
//   node repo-hygiene.mjs                 report only
//   node repo-hygiene.mjs --json          machine-readable
//   node repo-hygiene.mjs --fix           write descriptions for bare repos via hivemind workers
//
// Exit codes: 0 clean · 1 warnings · 2 critical (secrets exposed)

import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const USER = process.env.HYGIENE_USER || "Hanishchow";
const SITE = process.env.HYGIENE_SITE || "https://hanishchow.github.io";
const HIVEMIND = process.env.HIVEMIND_HOME ||
  join(dirname(dirname(fileURLToPath(import.meta.url))), "skills", "hivemind");

const ARGS = process.argv.slice(2);
const JSON_OUT = ARGS.includes("--json");
const FIX = ARGS.includes("--fix");

// Filenames that should never sit in a public repo. Presence only — never contents.
const SECRET_FILES = [
  /(^|\/)\.env$/, /(^|\/)\.env\.(?!example|sample|template)/, /(^|\/)id_[rd]sa$/, /\.pem$/,
  /(^|\/)credentials\.json$/, /(^|\/)service-account.*\.json$/, /(^|\/)\.npmrc$/,
  /(^|\/)\.pypirc$/, /(^|\/)secrets?\.(ya?ml|json|txt)$/i, /\.p12$/, /\.keystore$/,
];

const gh = (args) => {
  try {
    return execFileSync("gh", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  } catch (e) {
    return null;
  }
};
const ghJson = (args) => { const o = gh(args); try { return o ? JSON.parse(o) : null; } catch { return null; } };

// A CI runner blipping the network is not the same as a file being deleted.
// Retry, and only call it critical when the server actually answered with an
// error status - an unreachable host stays a warning so this never cries wolf.
async function httpOk(url, attempts = 3) {
  let last = { ok: false, status: 0, body: "", error: "not attempted" };
  for (let i = 0; i < attempts; i++) {
    try {
      const r = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(15000) });
      return { ok: r.ok, status: r.status, body: r.ok ? await r.text() : "", reachable: true };
    } catch (e) {
      last = { ok: false, status: 0, body: "", error: String(e).slice(0, 120), reachable: false };
      if (i < attempts - 1) await new Promise((res) => setTimeout(res, 2000 * (i + 1)));
    }
  }
  return last;
}

function auditRepos() {
  const repos = ghJson(["repo", "list", USER, "--limit", "200", "--source",
    "--visibility", "public", "--json", "name,description,repositoryTopics,isArchived"]) || [];
  const findings = [];

  for (const r of repos) {
    if (r.isArchived) continue;
    const tree = ghJson(["api", `repos/${USER}/${r.name}/git/trees/HEAD?recursive=1`,
      "--jq", "[.tree[]|select(.type==\"blob\")|.path]"]) || [];

    const leaked = tree.filter((p) => SECRET_FILES.some((re) => re.test(p)));
    if (leaked.length) {
      findings.push({ severity: "critical", repo: r.name, kind: "secret-file",
        detail: `tracked in a public repo: ${leaked.join(", ")}`,
        fix: `git rm --cached ${leaked[0]} && echo "${leaked[0]}" >> .gitignore  # then ROTATE the values` });
    }

    const desc = (r.description || "").trim();
    if (desc.length < 20) {
      findings.push({ severity: "warn", repo: r.name, kind: "bare-description",
        detail: desc ? `only ${desc.length} chars` : "no description",
        fix: "run with --fix to draft one via a hivemind worker" });
    }
    if ((r.repositoryTopics || []).length === 0 && tree.length > 3) {
      findings.push({ severity: "warn", repo: r.name, kind: "no-topics",
        detail: "zero topics — invisible to GitHub topic search", fix: "gh api -X PUT repos/OWNER/REPO/topics -f names[]=..." });
    }
    // the profile README repo is meant to hold one file - not a stub
    if (tree.length > 0 && tree.length <= 3 && r.name.toLowerCase() !== USER.toLowerCase()) {
      findings.push({ severity: "info", repo: r.name, kind: "stub",
        detail: `${tree.length} file(s) — an empty public repo is profile noise`,
        fix: "make it private or archive it" });
    }
  }
  return { repos, findings };
}

async function auditSite() {
  const findings = [];
  const home = await httpOk(SITE + "/");

  if (!home.ok) {
    const unreachable = home.reachable === false;
    findings.push({ severity: unreachable ? "warn" : "critical", repo: "site", kind: "site-down",
      detail: unreachable ? `${SITE}/ unreachable after 3 attempts (${home.error})` : `${SITE}/ returned ${home.status}`,
      fix: unreachable ? "probably transient; re-run" : "check GitHub Pages build" });
    return findings;
  }

  // Search-visibility assets. These silently revoke if the file disappears.
  const checks = [
    { path: "/robots.txt", kind: "robots" },
    { path: "/sitemap.xml", kind: "sitemap" },
    { path: "/google3e8c94787f2e78f6.html", kind: "google-verification-file" },
    { path: "/91e73d06675696a30a2a897d3d193f5b.txt", kind: "indexnow-key" },
  ];
  for (const c of checks) {
    const r = await httpOk(SITE + c.path);
    if (!r.ok) {
      const unreachable = r.reachable === false;
      findings.push({ severity: unreachable ? "warn" : "critical", repo: "site", kind: c.kind,
        detail: unreachable
          ? `${c.path} unreachable after 3 attempts (${r.error}) — probably transient, verify by hand`
          : `${c.path} returned ${r.status} — search verification breaks without it`,
        fix: unreachable ? `curl -I ${SITE}${c.path}` : `restore ${c.path} in the hanishchow.github.io repo` });
    }
  }

  if (!home.body.includes("google-site-verification")) {
    findings.push({ severity: "critical", repo: "site", kind: "google-verification-meta",
      detail: "verification meta tag missing from <head> — Search Console access will lapse",
      fix: "restore the meta tag in index.html" });
  }
  if (!/application\/ld\+json/.test(home.body)) {
    findings.push({ severity: "warn", repo: "site", kind: "schema",
      detail: "Person JSON-LD missing — search engines lose the entity association", fix: "restore the schema block" });
  }
  const sm = await httpOk(SITE + "/sitemap.xml");
  if (sm.ok) {
    for (const loc of [...sm.body.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1])) {
      const r = await httpOk(loc);
      if (!r.ok) findings.push({ severity: "warn", repo: "site", kind: "dead-sitemap-url",
        detail: `${loc} → ${r.status}`, fix: "remove it from sitemap.xml or fix the page" });
    }
  }
  return findings;
}

function auditProfile() {
  const p = ghJson(["api", `users/${USER}`, "--jq", "{name,bio,blog,location}"]) || {};
  const findings = [];
  for (const [field, why] of [["name", "your name"], ["bio", "a bio"], ["blog", "a website link"], ["location", "a location"]]) {
    const v = (p[field] || "").trim();
    if (!v) findings.push({ severity: "warn", repo: "profile", kind: `profile-${field}`,
      detail: `profile is missing ${why}`, fix: "https://github.com/settings/profile" });
    else if (v !== (p[field] || "")) findings.push({ severity: "warn", repo: "profile", kind: `profile-${field}`,
      detail: `${field} has leading/trailing whitespace`, fix: "re-save the field" });
  }
  return findings;
}

function fixDescriptions(bare) {
  const applied = [];
  for (const f of bare) {
    const tree = gh(["api", `repos/${USER}/${f.repo}/git/trees/HEAD?recursive=1`,
      "--jq", "[.tree[]|select(.type==\"blob\")|.path]|.[0:60]|join(\", \")"]) || "";
    const readme = gh(["api", `repos/${USER}/${f.repo}/readme`, "--jq", ".content"]) || "";
    let decoded = "";
    try { decoded = Buffer.from(readme, "base64").toString("utf8").slice(0, 3000); } catch {}
    const prompt =
      `Repository "${f.repo}". Files: ${tree}\n\nREADME:\n${decoded || "(none)"}\n\n` +
      `Reply with ONE line, max 100 chars: a plain-English GitHub description saying what this ` +
      `project DOES and its core tech. No emoji, no marketing words, no trailing period, no quotes.`;
    let res = null;
    try {
      res = execFileSync("node", [join(HIVEMIND, "scripts", "oc-worker.mjs"),
        "--run", "hygiene", "--label", f.repo, "--timeout", "300", prompt],
        { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
    } catch { res = null; }
    let desc = null;
    try { const j = JSON.parse((res || "").trim().split("\n").filter(Boolean).pop()); if (j.ok) desc = (j.result || "").trim().split("\n")[0].replace(/^["']|["']$/g, ""); } catch {}
    if (desc && desc.length > 15 && desc.length <= 160) {
      gh(["api", "-X", "PATCH", `repos/${USER}/${f.repo}`, "-f", `description=${desc}`]);
      applied.push({ repo: f.repo, description: desc });
    }
  }
  return applied;
}

const { findings: repoFindings } = auditRepos();
const findings = [...repoFindings, ...(await auditSite()), ...auditProfile()];
const rank = { critical: 0, warn: 1, info: 2 };
findings.sort((a, b) => rank[a.severity] - rank[b.severity] || a.repo.localeCompare(b.repo));

let applied = [];
if (FIX) applied = fixDescriptions(findings.filter((f) => f.kind === "bare-description"));

const crit = findings.filter((f) => f.severity === "critical");
const warn = findings.filter((f) => f.severity === "warn");

if (JSON_OUT) {
  console.log(JSON.stringify({ checked: new Date().toISOString(), findings, applied }, null, 2));
} else {
  const icon = { critical: "[!]", warn: " * ", info: " - " };
  console.log(`\nrepo hygiene — ${USER}\n${"=".repeat(46)}`);
  if (!findings.length) console.log("clean. nothing to do.");
  for (const f of findings) console.log(`${icon[f.severity]} ${f.repo.padEnd(28)} ${f.kind}\n      ${f.detail}\n      fix: ${f.fix}`);
  if (applied.length) {
    console.log(`\ndescriptions written (${applied.length}):`);
    for (const a of applied) console.log(`  ${a.repo}: ${a.description}`);
  }
  console.log(`\n${crit.length} critical · ${warn.length} warnings · ${findings.length} total`);
  if (crit.length) console.log("\ncritical findings mean something is exposed or your search verification is broken.");
}

process.exit(crit.length ? 2 : warn.length ? 1 : 0);
