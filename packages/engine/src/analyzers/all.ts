import type { Analyzer } from './types.ts';
import { securityAnalyzer } from './security.ts';
import { reliabilityAnalyzer } from './reliability.ts';
import { accessibilityAnalyzer } from './accessibility.ts';
import { performanceAnalyzer } from './performance.ts';
import { qualityAnalyzer } from './quality.ts';
import { scalabilityAnalyzer } from './scalability.ts';
import { testingAnalyzer } from './testing.ts';
import { devopsAnalyzer } from './devops.ts';
import { costAnalyzer } from './cost.ts';

/**
 * The analyzer registry.
 *
 * Order is irrelevant to correctness — analyzers are independent by contract —
 * but it determines the order warnings appear in, so the highest-value modules
 * run first.
 */
export const ALL_ANALYZERS: Analyzer[] = [
  securityAnalyzer,
  reliabilityAnalyzer,
  performanceAnalyzer,
  scalabilityAnalyzer,
  accessibilityAnalyzer,
  qualityAnalyzer,
  testingAnalyzer,
  devopsAnalyzer,
  costAnalyzer,
];
