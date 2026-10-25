#!/usr/bin/env node
/// <reference types="node" />
// RLS Check from the command line, e.g. in CI:
//   node src/cli.ts snapshot.json           -> prints a Markdown report
//   node src/cli.ts snapshot.json --fail-on high
// Exit code 1 when a finding is at or above --fail-on (default: high), so a pipeline can block a risky change.
import { readFileSync } from 'node:fs';

import { analyze, parseSnapshot, toMarkdown, type Severity } from './analyze.ts';

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const args = process.argv.slice(2);
const failIdx = args.indexOf('--fail-on');
const failOn = (failIdx >= 0 ? args[failIdx + 1] : 'high') as Severity;
const file = args.find((a, i) => !a.startsWith('--') && (failIdx < 0 || i !== failIdx + 1));

if (!ORDER.includes(failOn)) {
  console.error(`--fail-on must be one of: ${ORDER.join(', ')}`);
  process.exit(2);
}

const input = file ? readFileSync(file, 'utf8') : readFileSync(0, 'utf8');
let findings;
try {
  findings = analyze(parseSnapshot(input));
} catch (e) {
  console.error((e as Error).message);
  process.exit(2);
}
console.log(toMarkdown(findings));
const blocking = findings.filter((f) => ORDER.indexOf(f.severity) <= ORDER.indexOf(failOn));
process.exit(blocking.length ? 1 : 0);
