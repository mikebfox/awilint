import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { scanWorkflow } from "../src/index.js";

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cliPath = path.join(repoRoot, "src", "cli.js");

test("does not flag a normal non-agent workflow", () => {
  const result = scanWorkflow(
    `name: ci
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`,
    { path: "safe.yml" }
  );

  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.events, ["push"]);
});

test("flags untrusted issue text flowing into an agent prompt with write permissions", () => {
  const result = scanWorkflow(
    `name: triage
on:
  issues:
    types: [opened]
permissions: write-all
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          prompt: |
            Read this issue and label it:
            \${{ github.event.issue.body }}
        env:
          OPENAI_API_KEY: \${{ secrets.OPENAI_API_KEY }}
`,
    { path: "agent.yml" }
  );

  const ruleIds = result.findings.map((finding) => finding.ruleId);
  assert.ok(ruleIds.includes("AWI001"));
  assert.ok(ruleIds.includes("AWI002"));
  assert.ok(ruleIds.includes("AWI004"));
  assert.ok(ruleIds.includes("AWI005"));
});

test("flags untrusted pull request text inside agent shell commands", () => {
  const result = scanWorkflow(
    `name: review
on: [pull_request]
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - name: Claude review
        run: |
          claude -p "Review this title: \${{ github.event.pull_request.title }}"
`,
    { path: "review.yml" }
  );

  const ruleIds = result.findings.map((finding) => finding.ruleId);
  assert.ok(ruleIds.includes("AWI001"));
  assert.ok(ruleIds.includes("AWI003"));
});

test("flags pull_request_target checkout of attacker-controlled head code", () => {
  const result = scanWorkflow(
    `name: risky target
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: \${{ github.event.pull_request.head.repo.full_name }}
          ref: \${{ github.event.pull_request.head.sha }}
`,
    { path: "target.yml" }
  );

  assert.ok(result.findings.some((finding) => finding.ruleId === "AWI006"));
});

test("CLI emits JSON and honors --no-fail", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "awilint-"));
  const workflowDir = path.join(dir, ".github", "workflows");
  await mkdir(workflowDir, { recursive: true });
  await writeFile(
    path.join(workflowDir, "agent.yml"),
    `name: agent
on: [issue_comment]
permissions:
  issues: write
jobs:
  reply:
    runs-on: ubuntu-latest
    steps:
      - name: Codex reply
        run: codex --prompt "\${{ github.event.comment.body }}"
`,
    "utf8"
  );

  const result = spawnSync(process.execPath, [cliPath, workflowDir, "--json", "--no-fail"], {
    encoding: "utf8"
  });

  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.files.length, 1);
  assert.ok(report.totals.findings >= 2);
});
