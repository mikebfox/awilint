# awilint

`awilint` scans GitHub Actions workflow YAML for agentic workflow injection risks.

AI agents are moving into CI/CD: issue triage, PR review, release notes, repository maintenance, and safe-output writeback. That creates a specific failure mode: untrusted GitHub event text, such as issue bodies or PR descriptions, is inserted into prompts or shell commands while the same workflow has tokens, tools, or write permissions.

`awilint` is a small local first-pass scanner for that boundary. It is not a full GitHub Actions linter and it is not an MCP proxy. It focuses on explainable checks that are easy to run before a workflow gives an agent repository authority.

## Why this exists

Recent agent and supply-chain security work points at the same operational gap:

- Agentic workflows need stronger trust boundaries and input validation.
- AI-in-CI systems can turn issue, PR, or comment text into agent instructions.
- Compromised packages and GitHub Actions pipelines keep making CI credentials a high-value target.
- Agentic workflow platforms increasingly rely on read-only agent jobs, threat detection, and separated writeback.

`awilint` makes the pre-flight static check cheap: scan workflow text, find high-risk prompt lanes, and fix permissions before the agent runs.

## Install

```sh
npm install -D awilint
```

Requires Node.js 20 or newer.

## CLI usage

Scan the default workflow directory:

```sh
npx awilint
```

Scan explicit files or directories:

```sh
npx awilint .github/workflows/agent.yml workflows/
```

Use JSON output in CI:

```sh
npx awilint --json --fail-on medium
```

Read a workflow from stdin:

```sh
cat .github/workflows/agent.yml | npx awilint -
```

## Library usage

```js
import { scanWorkflow, formatTextReport } from "awilint";

const workflow = `
on:
  issues:
permissions: write-all
jobs:
  triage:
    steps:
      - uses: openai/codex-action@v1
        with:
          prompt: "\${{ github.event.issue.body }}"
`;

const result = scanWorkflow(workflow, { path: "triage.yml" });

console.log(result.findings);
console.log(formatTextReport(result));
```

## Checks

`awilint` currently reports:

- `AWI001`: untrusted GitHub event data reaches an agent prompt or input.
- `AWI002`: write permissions are available in an agentic workflow with untrusted triggers.
- `AWI003`: untrusted GitHub event data is interpolated inside a shell step.
- `AWI004`: an action in an agentic workflow is not pinned to a full commit SHA.
- `AWI005`: AI provider secrets are exposed to an agentic workflow with untrusted triggers.
- `AWI006`: `pull_request_target` checks out attacker-controlled pull request head code.

## API

### `scanWorkflow(source, options)`

Scans one workflow string.

Options:

- `path` or `filePath`: label used in reports.

Returns:

- `filePath`: report label.
- `events`: detected workflow events.
- `hasAgentSignals`: whether the file contains agent-related signals.
- `findings`: sorted findings with rule id, severity, line, snippet, refs, and remediation.
- `totals`: finding counts by severity.

### `scanWorkflows(inputs, options)`

Scans an array of strings or `{ path, content }` objects and returns an aggregate report.

### `formatTextReport(report)`

Formats a single-file or multi-file report for terminal output.

### `severityAtLeast(actual, threshold)`

Compares severities for CI fail logic.

## Design notes

`awilint` intentionally uses text-oriented workflow analysis instead of a heavyweight YAML parser. That keeps install cost low and lets it catch risky expressions inside folded blocks, shell snippets, and prompt strings without executing anything.

The tradeoff is deliberate: this is a fast pre-flight scanner, not a complete static taint engine. Pair it with general GitHub Actions hardening tools for broad workflow security. Use `awilint` when the question is narrow: "Could untrusted repository event text steer an agent that has tools, secrets, or write permissions?"

## Development

```sh
npm test
```

Run the CLI from the checkout:

```sh
node src/cli.js --json --no-fail
```

## License

MIT

## Background sources

- NSA: Model Context Protocol security design considerations for AI-driven automation.
- arXiv: "Demystifying and Detecting Agentic Workflow Injection Vulnerabilities in GitHub Actions."
- Aikido: "PromptPwnd: Prompt Injection Vulnerabilities in GitHub Actions Using AI Agents."
- TechRadar: Mini Shai-Hulud npm supply-chain compromise coverage.
- GitHub Agentic Workflows: threat detection and safe-output architecture.
