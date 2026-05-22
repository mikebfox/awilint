export type Severity = "low" | "medium" | "high";

export interface Finding {
  ruleId: "AWI001" | "AWI002" | "AWI003" | "AWI004" | "AWI005" | "AWI006";
  severity: Severity;
  line: number;
  message: string;
  snippet: string;
  refs: string[];
  remediation: string;
}

export interface WorkflowScanResult {
  version: string;
  filePath: string;
  events: string[];
  hasAgentSignals: boolean;
  findings: Finding[];
  totals: FindingTotals;
}

export interface WorkflowInput {
  path?: string;
  filePath?: string;
  content: string;
}

export interface MultiWorkflowScanResult {
  version: string;
  files: WorkflowScanResult[];
  totals: FindingTotals;
}

export interface FindingTotals {
  findings: number;
  bySeverity: Record<Severity, number>;
}

export interface ScanOptions {
  path?: string;
  filePath?: string;
}

export const VERSION: string;

export function scanWorkflow(source: string, options?: ScanOptions): WorkflowScanResult;

export function scanWorkflows(
  inputs: Array<string | WorkflowInput>,
  options?: ScanOptions
): MultiWorkflowScanResult;

export function formatTextReport(report: WorkflowScanResult | MultiWorkflowScanResult): string;

export function severityAtLeast(actual: Severity, threshold: Severity): boolean;

export function summarizeFindings(findings: Finding[]): FindingTotals;
