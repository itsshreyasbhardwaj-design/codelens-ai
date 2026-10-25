import type { Analyzer } from './types.ts';
import { securityAnalyzer } from './security.ts';
import { accessibilityAnalyzer } from './accessibility.ts';
import { performanceAnalyzer } from './performance.ts';
import { qualityAnalyzer } from './quality.ts';
import { scalabilityAnalyzer } from './scalability.ts';
import { testingAnalyzer } from './testing.ts';

/**
 * The analyzer registry.
 *
 * Order is irrelevant to correctness — analyzers are independent by contract —
 * but it determines the order warnings appear in, so the highest-value modules
 * run first.
 */
export const ALL_ANALYZERS: Analyzer[] = [
  securityAnalyzer,
  performanceAnalyzer,
  scalabilityAnalyzer,
  accessibilityAnalyzer,
  qualityAnalyzer,
  testingAnalyzer,
];
