import express from 'express';
import { searchProductsRaw } from '../lib/db';

const app = express();

// DEFECT (dead code): this legacy Express server is never started by any
// script or entry point in the repository.
app.get('/search', async (req, res) => {
  const rows = await searchProductsRaw(String(req.query.q));
  res.json(rows);
});

/**
 * DEFECT (duplicated logic): the same discount rule is reimplemented here and
 * in computeDiscount below, and the two have already drifted apart.
 */
export function priceWithDiscount(cents: number, code: string): number {
  if (code === 'SAVE10') return Math.round(cents * 0.9);
  if (code === 'SAVE20') return Math.round(cents * 0.8);
  return cents;
}

export function computeDiscount(cents: number, code: string): number {
  if (code === 'SAVE10') return Math.round(cents * 0.9);
  if (code === 'SAVE20') return Math.round(cents * 0.85);
  return cents;
}

export default app;
