import { PrismaClient } from '@prisma/client';
import { Pool } from 'pg';

export const prisma = new PrismaClient();
export const pool = new Pool({ connectionString: process.env.DATABASE_URL });

/**
 * DEFECT (SQL injection): the search term is concatenated straight into SQL.
 * A value like `'; DROP TABLE "Order"; --` executes as statement text.
 */
export async function searchProductsRaw(term: string) {
  const sql = `SELECT * FROM "Product" WHERE name LIKE '%${term}%'`;
  const result = await pool.query(sql);
  return result.rows;
}

/**
 * DEFECT (unbounded query): no take/limit, so the whole table is loaded into
 * memory and serialised on every call.
 */
export async function listAllProducts() {
  return prisma.product.findMany();
}
