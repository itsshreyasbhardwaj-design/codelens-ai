import { NextResponse } from 'next/server';
import { writeFile } from 'node:fs/promises';

/**
 * DEFECT (unsafe file upload): no content-type allowlist, no size limit, and
 * the client-supplied filename is used directly in the destination path, so a
 * name containing ../ writes outside the upload directory.
 */
export async function POST(req: Request) {
  const form = await req.formData();
  const file = form.get('file') as File;
  const buffer = Buffer.from(await file.arrayBuffer());
  await writeFile(`./public/uploads/${file.name}`, buffer);
  return NextResponse.json({ url: `/uploads/${file.name}` });
}

/**
 * DEFECT (SSRF): a URL supplied in the request body is fetched directly, so a
 * caller can reach internal addresses such as 169.254.169.254 or localhost.
 */
export async function PUT(req: Request) {
  const { url } = await req.json();
  const res = await fetch(url);
  return NextResponse.json({ status: res.status, body: await res.text() });
}
