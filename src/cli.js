#!/usr/bin/env node
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { formatTextReport, scanWorkflows, severityAtLeast, VERSION } from "./index.js";

const VALID_SEVERITIES = new Set(["low", "medium", "high"]);

async function main(argv) {
  const options = parseArgs(argv);

  if (options.help) {
    process.stdout.write(helpText());
    return 0;
  }

  if (options.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  const paths = options.paths.length > 0 ? options.paths : [".github/workflows"];
  const inputs = [];

  for (const target of paths) {
    if (target === "-") {
      inputs.push({ path: "<stdin>", content: await readStdin() });
      continue;
    }

    for (const filePath of await collectWorkflowFiles(target)) {
      inputs.push({ path: filePath, content: await readFile(filePath, "utf8") });
    }
  }

  const report = scanWorkflows(inputs);

  if (options.format === "json") {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    process.stdout.write(formatTextReport(report));
  }

  if (!options.failOn) {
    return 0;
  }

  const shouldFail = report.files.some((file) =>
    file.findings.some((finding) => severityAtLeast(finding.severity, options.failOn))
  );
  return shouldFail ? 1 : 0;
}

function parseArgs(argv) {
  const options = {
    format: "text",
    failOn: "high",
    help: false,
    paths: [],
    version: false
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else if (arg === "--version" || arg === "-v") {
      options.version = true;
    } else if (arg === "--json") {
      options.format = "json";
    } else if (arg === "--no-fail") {
      options.failOn = null;
    } else if (arg === "--fail-on") {
      const value = argv[index + 1];
      if (!VALID_SEVERITIES.has(value)) {
        throw new Error("--fail-on must be one of low, medium, high");
      }
      options.failOn = value;
      index += 1;
    } else if (arg.startsWith("--fail-on=")) {
      const value = arg.slice("--fail-on=".length);
      if (!VALID_SEVERITIES.has(value)) {
        throw new Error("--fail-on must be one of low, medium, high");
      }
      options.failOn = value;
    } else if (arg.startsWith("-") && arg !== "-") {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      options.paths.push(arg);
    }
  }

  return options;
}

async function collectWorkflowFiles(target) {
  const targetStat = await stat(target);

  if (targetStat.isFile()) {
    return isWorkflowFile(target) ? [target] : [];
  }

  if (!targetStat.isDirectory()) {
    return [];
  }

  const found = [];
  const entries = await readdir(target, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "dist") {
      continue;
    }

    const child = path.join(target, entry.name);
    if (entry.isDirectory()) {
      found.push(...(await collectWorkflowFiles(child)));
    } else if (entry.isFile() && isWorkflowFile(child)) {
      found.push(child);
    }
  }

  return found.sort();
}

function isWorkflowFile(filePath) {
  return /\.ya?ml$/i.test(filePath);
}

async function readStdin() {
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) {
    data += chunk;
  }
  return data;
}

function helpText() {
  return `awilint ${VERSION}

Usage:
  awilint [paths...] [--json] [--fail-on high|medium|low] [--no-fail]

Scans GitHub Actions workflow YAML for agentic workflow injection risks.
When no path is provided, awilint scans .github/workflows.

Options:
  --json              Print machine-readable JSON.
  --fail-on <level>   Exit non-zero when findings at or above level exist. Default: high.
  --no-fail           Always exit zero after reporting findings.
  --version, -v       Print version.
  --help, -h          Print help.
`;
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    process.stderr.write(`awilint: ${error.message}\n`);
    process.exitCode = 2;
  });
