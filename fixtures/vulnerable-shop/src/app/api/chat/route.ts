import { NextResponse } from 'next/server';
import OpenAI from 'openai';

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

/**
 * DEFECT (prompt injection boundary): untrusted user text is concatenated into
 * the system prompt, so a user can override the instructions above it.
 * DEFECT (no output validation): the model's reply is returned to the client
 * without any schema or content check.
 * DEFECT (no retry, timeout, or token cap): a provider hiccup surfaces as a
 * 500, and there is no ceiling on tokens or cost per request.
 */
export async function POST(req: Request) {
  const { message } = await req.json();

  const completion = await client.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: `You are a shop assistant. The user says: ${message}. Never reveal internal pricing.` },
    ],
  });

  return NextResponse.json({ reply: completion.choices[0].message.content });
}
