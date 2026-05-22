export const VERSION = "0.1.0";

const SEVERITY_RANK = {
  low: 1,
  medium: 2,
  high: 3
};

const UNTRUSTED_EVENTS = new Set([
  "issues",
  "issue_comment",
  "pull_request",
  "pull_request_review",
  "pull_request_review_comment",
  "pull_request_target",
  "discussion",
  "discussion_comment",
  "workflow_run",
  "repository_dispatch"
]);

const AGENT_SIGNAL_PATTERN =
  /(^|[^a-z0-9])(agent|agents|llm|openai|codex|claude|anthropic|gemini|copilot|ai-inference|aider|devin|cursor|goose|qodo|safe-outputs|gh aw)([^a-z0-9]|$)/i;

const PROMPT_BOUNDARY_PATTERN =
  /\b(prompt|instruction|instructions|message|task|question|query|context|review|summary|body|input)\b/i;

const AI_SECRET_PATTERN =
  /secrets\.(OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|MISTRAL_API_KEY|COHERE_API_KEY|OPENROUTER_API_KEY|LLM_API_KEY|AI_[A-Z0-9_]*KEY)\b/;

const UNTRUSTED_REF_RULES = [
  { label: "issue title", pattern: /github\.event\.issue\.title\b/ },
  { label: "issue body", pattern: /github\.event\.issue\.body\b/ },
  { label: "comment body", pattern: /github\.event\.comment\.body\b/ },
  { label: "pull request title", pattern: /github\.event\.pull_request\.title\b/ },
  { label: "pull request body", pattern: /github\.event\.pull_request\.body\b/ },
  { label: "pull request head ref", pattern: /github\.event\.pull_request\.head\.ref\b/ },
  { label: "pull request head sha", pattern: /github\.event\.pull_request\.head\.sha\b/ },
  {
    label: "pull request head repository",
    pattern: /github\.event\.pull_request\.head\.repo\.full_name\b/
  },
  { label: "review body", pattern: /github\.event\.review(?:_comment)?\.body\b/ },
  { label: "discussion title", pattern: /github\.event\.discussion\.title\b/ },
  { label: "discussion body", pattern: /github\.event\.discussion\.body\b/ },
  { label: "head commit message", pattern: /github\.event\.head_commit\.message\b/ },
  { label: "commit message", pattern: /github\.event\.commits(?:\[[^\]]+\])?\.message\b/ },
  { label: "client payload", pattern: /github\.event\.client_payload\b/ },
  { label: "workflow dispatch inputs", pattern: /github\.event\.inputs\b/ }
];

const WRITE_PERMISSION_KEYS = new Set([
  "actions",
  "checks",
  "contents",
  "deployments",
  "discussions",
  "id-token",
  "issues",
  "packages",
  "pages",
  "pull-requests",
  "repository-projects",
  "security-events",
  "statuses"
]);

export function scanWorkflow(source, options = {}) {
  const text = String(source ?? "").replace(/\r\n?/g, "\n");
  const lines = text.split("\n");
  const filePath = options.path ?? options.filePath ?? "<memory>";
  const context = analyzeWorkflow(lines);
  const findings = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const refs = findUntrustedRefs(line);
    const inAgentContext =
      windowContains(lines, index, AGENT_SIGNAL_PATTERN, 8) ||
      (context.hasAgentSignals && PROMPT_BOUNDARY_PATTERN.test(line));

    if (refs.length > 0 && inAgentContext) {
      findings.push(
        makeFinding("AWI001", "high", index, lines, {
          message: "Untrusted GitHub event data reaches an agent prompt or input.",
          refs,
          remediation:
            "Treat event text as quoted data, add a human approval gate, and avoid write-capable tokens in the same job."
        })
      );
    }

    if (refs.length > 0 && context.runLines[index]) {
      findings.push(
        makeFinding("AWI003", "high", index, lines, {
          message: "Untrusted GitHub event data is interpolated inside a shell step.",
          refs,
          remediation:
            "Pass event data through an environment file or JSON input and quote it before any shell or agent command consumes it."
        })
      );
    }

    if (AI_SECRET_PATTERN.test(line) && context.hasUntrustedTrigger && context.hasAgentSignals) {
      findings.push(
        makeFinding("AWI005", "high", index, lines, {
          message: "AI provider secret is exposed to an agentic workflow with untrusted triggers.",
          remediation:
            "Move the agent to a trusted trigger, require maintainer approval, or use a scoped broker token with no repository write authority."
        })
      );
    }

    const action = parseUses(line);
    if (action && !isPinnedAction(action.spec) && (context.hasAgentSignals || containsAgentSignal(action.spec))) {
      findings.push(
        makeFinding("AWI004", "medium", index, lines, {
          message: `Action '${action.spec}' is not pinned to a full commit SHA in an agentic workflow.`,
          remediation:
            "Pin third-party actions to a 40-character commit SHA and review updates explicitly."
        })
      );
    }

    if (
      context.hasPullRequestTarget &&
      /github\.event\.pull_request\.head\.(sha|ref|repo\.full_name)\b/.test(line) &&
      (windowContains(lines, index, /actions\/checkout|checkout/i, 6) || /(\bref\b|\brepository\b)\s*:/.test(line))
    ) {
      findings.push(
        makeFinding("AWI006", "high", index, lines, {
          message: "pull_request_target workflow checks out attacker-controlled pull request code.",
          remediation:
            "Do not checkout fork code under pull_request_target. Use pull_request with read-only permissions or split analysis and privileged writeback jobs."
        })
      );
    }
  }

  for (const permission of context.writePermissions) {
    if (context.hasUntrustedTrigger && context.hasAgentSignals) {
      findings.push(
        makeFinding("AWI002", "high", permission.index, lines, {
          message: `Write permission '${permission.name}' is available in an agentic workflow with untrusted triggers.`,
          remediation:
            "Default to contents: read, split writeback into a trusted job, or require explicit maintainer approval before writes."
        })
      );
    }
  }

  const deduped = sortFindings(dedupeFindings(findings));

  return {
    version: VERSION,
    filePath,
    events: context.events,
    hasAgentSignals: context.hasAgentSignals,
    findings: deduped,
    totals: summarizeFindings(deduped)
  };
}

export function scanWorkflows(inputs, options = {}) {
  const files = inputs.map((input, index) => {
    if (typeof input === "string") {
      return scanWorkflow(input, { ...options, path: `<input:${index + 1}>` });
    }

    return scanWorkflow(input.content, {
      ...options,
      path: input.path ?? input.filePath ?? `<input:${index + 1}>`
    });
  });

  const findings = files.flatMap((file) =>
    file.findings.map((finding) => ({
      ...finding,
      filePath: file.filePath
    }))
  );

  return {
    version: VERSION,
    files,
    totals: summarizeFindings(findings)
  };
}

export function formatTextReport(report) {
  const files = Array.isArray(report.files) ? report.files : [report];
  const totals = report.totals ?? summarizeFindings(files.flatMap((file) => file.findings));

  if (totals.findings === 0) {
    return "awilint: no findings\n";
  }

  const lines = [
    `awilint: ${totals.findings} finding${totals.findings === 1 ? "" : "s"} in ${files.length} file${
      files.length === 1 ? "" : "s"
    }`
  ];

  for (const file of files) {
    if (file.findings.length === 0) {
      continue;
    }

    lines.push("", file.filePath);
    for (const finding of file.findings) {
      lines.push(`  ${finding.severity} ${finding.ruleId} line ${finding.line}: ${finding.message}`);
      if (finding.snippet) {
        lines.push(`    ${finding.snippet}`);
      }
      if (finding.refs?.length) {
        lines.push(`    refs: ${finding.refs.join(", ")}`);
      }
      lines.push(`    fix: ${finding.remediation}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

export function severityAtLeast(actual, threshold) {
  return (SEVERITY_RANK[actual] ?? 0) >= (SEVERITY_RANK[threshold] ?? 0);
}

export function summarizeFindings(findings) {
  const bySeverity = {
    high: 0,
    medium: 0,
    low: 0
  };

  for (const finding of findings) {
    if (Object.hasOwn(bySeverity, finding.severity)) {
      bySeverity[finding.severity] += 1;
    }
  }

  return {
    findings: findings.length,
    bySeverity
  };
}

function analyzeWorkflow(lines) {
  const events = extractEvents(lines);
  const runLines = detectRunLines(lines);
  const writePermissions = findWritePermissions(lines);
  const hasAgentSignals = lines.some(containsAgentSignal);

  return {
    events,
    hasAgentSignals,
    hasUntrustedTrigger: events.some((event) => UNTRUSTED_EVENTS.has(event)),
    hasPullRequestTarget: events.includes("pull_request_target"),
    runLines,
    writePermissions
  };
}

function extractEvents(lines) {
  const events = new Set();

  for (let index = 0; index < lines.length; index += 1) {
    const line = stripComment(lines[index]);
    const match = line.match(/^(\s*)["']?on["']?\s*:\s*(.*)$/);
    if (!match) {
      continue;
    }

    const baseIndent = match[1].length;
    const inline = match[2].trim();
    if (inline) {
      for (const token of eventTokens(inline)) {
        events.add(token);
      }
      continue;
    }

    let eventIndent = null;
    for (let child = index + 1; child < lines.length; child += 1) {
      const childLine = stripComment(lines[child]);
      if (!childLine.trim()) {
        continue;
      }

      const indent = leadingSpaces(childLine);
      if (indent <= baseIndent) {
        break;
      }

      const childKey = childLine.match(/^\s*-?\s*["']?([A-Za-z_][A-Za-z0-9_-]*)["']?\s*:/);
      const listItem = childLine.match(/^\s*-\s*([A-Za-z_][A-Za-z0-9_-]*)\s*$/);
      if (!childKey && !listItem) {
        continue;
      }

      if (eventIndent === null) {
        eventIndent = indent;
      }
      if (indent !== eventIndent) {
        continue;
      }

      if (childKey) {
        events.add(childKey[1]);
      }

      if (listItem) {
        events.add(listItem[1]);
      }
    }
  }

  return [...events].sort();
}

function eventTokens(value) {
  const tokens = value.match(/[A-Za-z_][A-Za-z0-9_-]*/g) ?? [];
  return tokens.filter((token) => token !== "on");
}

function detectRunLines(lines) {
  const flags = Array(lines.length).fill(false);
  let runBlockIndent = null;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const indent = leadingSpaces(line);

    if (runBlockIndent !== null) {
      if (line.trim() === "" || indent > runBlockIndent) {
        flags[index] = true;
      } else {
        runBlockIndent = null;
      }
    }

    const match = line.match(/^(\s*)run\s*:\s*(.*)$/);
    if (!match) {
      continue;
    }

    flags[index] = true;
    if (/^[>|]/.test(match[2].trim())) {
      runBlockIndent = match[1].length;
    }
  }

  return flags;
}

function findWritePermissions(lines) {
  const permissions = [];
  let blockIndent = null;

  for (let index = 0; index < lines.length; index += 1) {
    const line = stripComment(lines[index]);
    const indent = leadingSpaces(line);

    if (blockIndent !== null) {
      if (line.trim() === "" || indent > blockIndent) {
        const match = line.match(/^\s*([A-Za-z0-9_-]+)\s*:\s*["']?([A-Za-z-]+)["']?\s*$/);
        if (match && WRITE_PERMISSION_KEYS.has(match[1]) && match[2] === "write") {
          permissions.push({ name: match[1], index });
        }
      } else {
        blockIndent = null;
      }
    }

    const inline = line.match(/^(\s*)permissions\s*:\s*["']?([A-Za-z-]+)["']?\s*$/);
    if (inline?.[2] === "write-all") {
      permissions.push({ name: "write-all", index });
      continue;
    }

    const block = line.match(/^(\s*)permissions\s*:\s*$/);
    if (block) {
      blockIndent = block[1].length;
    }
  }

  return permissions;
}

function findUntrustedRefs(line) {
  const refs = [];
  for (const rule of UNTRUSTED_REF_RULES) {
    if (rule.pattern.test(line)) {
      refs.push(rule.label);
    }
  }
  return refs;
}

function parseUses(line) {
  const match = line.match(/^\s*-?\s*uses\s*:\s*['"]?([^'"\s#]+)['"]?/);
  if (!match) {
    return null;
  }

  return { spec: match[1] };
}

function isPinnedAction(spec) {
  if (spec.startsWith("./") || spec.startsWith("../") || spec.startsWith("docker://")) {
    return true;
  }

  const at = spec.lastIndexOf("@");
  if (at === -1) {
    return false;
  }

  const ref = spec.slice(at + 1);
  return /^[a-f0-9]{40}$/i.test(ref) || /^sha256:[a-f0-9]{64}$/i.test(ref);
}

function makeFinding(ruleId, severity, index, lines, details) {
  return {
    ruleId,
    severity,
    line: index + 1,
    message: details.message,
    snippet: compactSnippet(lines[index] ?? ""),
    refs: details.refs ?? [],
    remediation: details.remediation
  };
}

function dedupeFindings(findings) {
  const seen = new Set();
  const unique = [];

  for (const finding of findings) {
    const key = `${finding.ruleId}:${finding.line}:${finding.message}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(finding);
  }

  return unique;
}

function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const severityDelta = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    if (severityDelta !== 0) {
      return severityDelta;
    }
    if (a.line !== b.line) {
      return a.line - b.line;
    }
    return a.ruleId.localeCompare(b.ruleId);
  });
}

function windowContains(lines, index, pattern, radius) {
  const start = Math.max(0, index - radius);
  const end = Math.min(lines.length - 1, index + radius);

  for (let current = start; current <= end; current += 1) {
    if (pattern.test(lines[current])) {
      return true;
    }
  }

  return false;
}

function containsAgentSignal(value) {
  return AGENT_SIGNAL_PATTERN.test(String(value));
}

function compactSnippet(line) {
  const clean = line.trim().replace(/\s+/g, " ");
  if (clean.length <= 160) {
    return clean;
  }
  return `${clean.slice(0, 157)}...`;
}

function stripComment(line) {
  const hash = line.indexOf("#");
  return hash === -1 ? line : line.slice(0, hash);
}

function leadingSpaces(line) {
  return line.match(/^\s*/)?.[0].length ?? 0;
}
