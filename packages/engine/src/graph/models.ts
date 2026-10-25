import type { DataModel } from '@codelens/core';
import type { SourceFile } from '../ingest/normalize.ts';
import type { ParsedModule } from '../parse/types.ts';

/**
 * Data model extraction: Prisma schemas, SQL DDL, and ORM model classes.
 *
 * `ownershipField` is the column that ties a row to a user. It is what the
 * authorisation analyzer needs to decide whether a query that reads a row is
 * scoped to its owner.
 */

const OWNERSHIP_FIELD_NAMES = [
  'userId', 'user_id', 'ownerId', 'owner_id', 'accountId', 'account_id',
  'organizationId', 'organization_id', 'orgId', 'tenantId', 'tenant_id',
  'customerId', 'customer_id', 'createdById', 'authorId', 'author_id',
];

function pickOwnershipField(fields: DataModel['fields']): string | undefined {
  return fields.find((f) => OWNERSHIP_FIELD_NAMES.includes(f.name))?.name;
}

/** Parse a `schema.prisma` file into models. */
export function parsePrismaSchema(file: SourceFile): DataModel[] {
  const text = file.text;
  if (!text) return [];
  const out: DataModel[] = [];

  // Match `model Name { ... }` blocks.
  const blockRe = /(?:^|\n)\s*model\s+(\w+)\s*\{([\s\S]*?)\n\s*\}/g;
  let m: RegExpExecArray | null;
  while ((m = blockRe.exec(text)) !== null) {
    const name = m[1]!;
    const body = m[2]!;
    const fields: DataModel['fields'] = [];
    const relations: DataModel['relations'] = [];
    const indexes: string[] = [];

    for (const rawLine of body.split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('//')) continue;

      if (line.startsWith('@@index') || line.startsWith('@@unique')) {
        const inner = /\[([^\]]+)\]/.exec(line)?.[1];
        if (inner) indexes.push(inner.split(',').map((s) => s.trim()).join('+'));
        continue;
      }
      if (line.startsWith('@@')) continue;

      const fm = /^(\w+)\s+(\w+)(\[\])?(\?)?(.*)$/.exec(line);
      if (!fm) continue;
      const [, fieldName, fieldType, isList, optional, rest = ''] = fm;

      // A field whose type is another model is a relation, not a column.
      const isRelation = /@relation/.test(rest) || (!!isList && /^[A-Z]/.test(fieldType!));
      if (isRelation) {
        relations.push({ to: fieldType!, kind: isList ? 'has_many' : 'belongs_to' });
        if (!/@relation/.test(rest)) continue;
      }

      fields.push({
        name: fieldName!,
        type: fieldType! + (isList ? '[]' : ''),
        nullable: !!optional,
        unique: /@unique/.test(rest) || /@id/.test(rest),
      });
      if (/@id/.test(rest) || /@unique/.test(rest)) indexes.push(fieldName!);
    }

    out.push({
      name, file: file.path, kind: 'orm_model',
      fields, relations, indexes,
      ownershipField: pickOwnershipField(fields),
    });
  }
  return out;
}

/** Parse CREATE TABLE statements from a .sql file. */
export function parseSqlDdl(file: SourceFile): DataModel[] {
  const text = file.text;
  if (!text) return [];
  const out: DataModel[] = [];
  const tableRe = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["`[]?(\w+)["`\]]?\s*\(([\s\S]*?)\n\s*\)\s*;/gi;
  let m: RegExpExecArray | null;
  while ((m = tableRe.exec(text)) !== null) {
    const name = m[1]!;
    const fields: DataModel['fields'] = [];
    const relations: DataModel['relations'] = [];
    const indexes: string[] = [];
    for (const rawLine of m[2]!.split('\n')) {
      const line = rawLine.trim().replace(/,$/, '');
      if (!line || line.startsWith('--')) continue;
      if (/^(PRIMARY\s+KEY|UNIQUE|CHECK|CONSTRAINT|FOREIGN\s+KEY)/i.test(line)) {
        const fk = /REFERENCES\s+["`[]?(\w+)/i.exec(line);
        if (fk) relations.push({ to: fk[1]!, kind: 'references' });
        const cols = /\(([^)]+)\)/.exec(line)?.[1];
        if (cols && /^(PRIMARY\s+KEY|UNIQUE)/i.test(line)) {
          indexes.push(cols.split(',').map((s) => s.trim().replace(/["`]/g, '')).join('+'));
        }
        continue;
      }
      const fm = /^["`[]?(\w+)["`\]]?\s+([A-Za-z0-9_ ]+?)(\s|$)/.exec(line);
      if (!fm) continue;
      const fk = /REFERENCES\s+["`[]?(\w+)/i.exec(line);
      if (fk) relations.push({ to: fk[1]!, kind: 'references' });
      fields.push({
        name: fm[1]!, type: fm[2]!.trim(),
        nullable: !/NOT\s+NULL/i.test(line),
        unique: /UNIQUE|PRIMARY\s+KEY/i.test(line),
      });
    }
    out.push({
      name, file: file.path, kind: 'sql_table',
      fields, relations, indexes, ownershipField: pickOwnershipField(fields),
    });
  }

  // Standalone CREATE INDEX statements belong to their table.
  const idxRe = /CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?\w+\s+ON\s+["`[]?(\w+)["`\]]?\s*\(([^)]+)\)/gi;
  while ((m = idxRe.exec(text)) !== null) {
    const table = out.find((t) => t.name.toLowerCase() === m![1]!.toLowerCase());
    if (table) table.indexes.push(m[2]!.split(',').map((s) => s.trim().replace(/["`]/g, '')).join('+'));
  }
  return out;
}

/** ORM model classes in parsed modules (Django, SQLAlchemy, TypeORM, Mongoose). */
export function extractOrmModels(modules: Map<string, ParsedModule>): DataModel[] {
  const out: DataModel[] = [];
  for (const mod of modules.values()) {
    if (!mod.parsed) continue;

    for (const sym of mod.symbols) {
      if (sym.kind !== 'class') continue;
      const text = sym.text;

      const isDjango = /\bmodels\.Model\b/.test(text) || /models\.\w+Field\s*\(/.test(text);
      const isSqlAlchemy = /\b__tablename__\b/.test(text) || /\bColumn\s*\(/.test(text);
      const isTypeOrm = (sym.decorators ?? []).some((d) => /@Entity/.test(d));
      if (!isDjango && !isSqlAlchemy && !isTypeOrm) continue;

      const fields: DataModel['fields'] = [];
      const relations: DataModel['relations'] = [];
      const indexes: string[] = [];

      // Django / SQLAlchemy field assignments.
      for (const fm of text.matchAll(/^\s*(\w+)\s*(?::\s*[\w\[\], ]+)?=\s*(?:models\.(\w+)|Column\s*\(\s*(\w+)|relationship\s*\(\s*['"](\w+))/gm)) {
        const fname = fm[1]!;
        const djangoType = fm[2];
        const sqlaType = fm[3];
        const relTarget = fm[4];
        if (relTarget) { relations.push({ to: relTarget, kind: 'relationship' }); continue; }
        if (djangoType && /ForeignKey|OneToOneField|ManyToManyField/.test(djangoType)) {
          const target = /\(\s*['"]?(\w+)/.exec(text.slice(fm.index!))?.[1];
          relations.push({ to: target ?? 'unknown', kind: djangoType });
        }
        fields.push({
          name: fname, type: djangoType ?? sqlaType ?? 'unknown',
          nullable: /null\s*=\s*True|nullable\s*=\s*True/.test(text.slice(fm.index!, fm.index! + 200)),
          unique: /unique\s*=\s*True|primary_key\s*=\s*True/.test(text.slice(fm.index!, fm.index! + 200)),
        });
      }
      // TypeORM / Mongoose decorated properties.
      for (const fm of text.matchAll(/@(?:Column|PrimaryGeneratedColumn|PrimaryColumn)\s*\([^)]*\)\s*\n?\s*(\w+)/g)) {
        fields.push({ name: fm[1]!, type: 'column', nullable: false, unique: false });
      }
      if (fields.length === 0) continue;

      out.push({
        name: sym.name, file: mod.path, kind: 'orm_model',
        fields, relations, indexes, ownershipField: pickOwnershipField(fields),
      });
    }
  }
  return out;
}

export function extractDataModels(
  files: SourceFile[], modules: Map<string, ParsedModule>,
): DataModel[] {
  const out: DataModel[] = [];
  for (const f of files) {
    if (f.path.endsWith('schema.prisma')) out.push(...parsePrismaSchema(f));
    else if (f.language === 'sql') out.push(...parseSqlDdl(f));
  }
  out.push(...extractOrmModels(modules));
  return out;
}
