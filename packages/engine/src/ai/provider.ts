/**
 * Provider-agnostic model access.
 *
 * Default is `none`. The product's deterministic layers produce every finding on
 * their own, so a scan with no provider configured is complete and reproducible
 * rather than degraded. That is deliberate: it keeps default scans free, offline,
 * and byte-for-byte repeatable, and it means no repository content leaves the
 * machine unless the operator explicitly opts in.
 *
 * Cost control is enforced here, not left to the caller: every request is
 * metered and a request that would exceed the configured budget is refused.
 */

export type ProviderName = 'none' | 'ollama' | 'anthropic' | 'openai';

export interface ModelRequest {
  system: string;
  user: string;
  /** JSON Schema the response must satisfy. Enforced by the caller via validate(). */
  schema?: Record<string, unknown>;
  maxOutputTokens?: number;
  temperature?: number;
}

export interface ModelResponse {
  text: string;
  tokensIn: number;
  tokensOut: number;
  model: string;
  provider: ProviderName;
}

export class ProviderDisabled extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(reason);
    this.name = 'ProviderDisabled';
    this.reason = reason;
  }
}

export class BudgetExceeded extends Error {
  constructor(spent: number, budget: number) {
    super(`AI token budget exhausted: ${spent} of ${budget} tokens used. Layer C aborted rather than spending beyond the configured ceiling.`);
    this.name = 'BudgetExceeded';
  }
}

export interface AiConfig {
  provider: ProviderName;
  model: string;
  /** Hard ceiling on total tokens for one scan. */
  tokenBudget: number;
  ollamaUrl: string;
  apiKey?: string;
  /**
   * True when the operator has acknowledged that repository content will be
   * sent to a third party. Required for anthropic/openai; never required for
   * `none` or `ollama`, which keep content on the machine.
   */
  externalTransferAcknowledged: boolean;
}

/** Read configuration from the environment, defaulting to fully disabled. */
export function loadAiConfig(env: Record<string, string | undefined> = process.env): AiConfig {
  const provider = (env.CODELENS_AI_PROVIDER ?? 'none') as ProviderName;
  const budget = Number(env.CODELENS_AI_TOKEN_BUDGET ?? '120000');
  const defaultModels: Record<ProviderName, string> = {
    none: '',
    ollama: 'qwen2.5-coder:7b',
    anthropic: 'claude-sonnet-5-5',
    openai: 'gpt-4o-mini',
  };
  return {
    provider: ['none', 'ollama', 'anthropic', 'openai'].includes(provider) ? provider : 'none',
    model: env.CODELENS_AI_MODEL || defaultModels[provider] || '',
    tokenBudget: Number.isFinite(budget) && budget > 0 ? budget : 120_000,
    ollamaUrl: env.CODELENS_OLLAMA_URL ?? 'http://127.0.0.1:11434',
    apiKey: provider === 'anthropic' ? env.ANTHROPIC_API_KEY : provider === 'openai' ? env.OPENAI_API_KEY : undefined,
    // Local providers never transfer content off the machine, so consent is implicit.
    externalTransferAcknowledged:
      provider === 'none' || provider === 'ollama'
        ? true
        : env.CODELENS_AI_ACCEPT_EXTERNAL_TRANSFER === 'true',
  };
}

/** Rough token estimate (~4 characters per token) for budgeting before a call. */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

export interface UsageRecord {
  provider: ProviderName;
  model: string;
  tokensIn: number;
  tokensOut: number;
  requests: number;
}

export class ModelClient {
  readonly config: AiConfig;
  private spentIn = 0;
  private spentOut = 0;
  private requests = 0;

  constructor(config: AiConfig) {
    this.config = config;
  }

  get usage(): UsageRecord {
    return {
      provider: this.config.provider,
      model: this.config.model,
      tokensIn: this.spentIn,
      tokensOut: this.spentOut,
      requests: this.requests,
    };
  }

  get spent(): number {
    return this.spentIn + this.spentOut;
  }

  get remaining(): number {
    return Math.max(0, this.config.tokenBudget - this.spent);
  }

  /**
   * Why this client cannot be used, or undefined when it can.
   * Checked once before the AI stage runs so the stage is reported as skipped
   * with a real reason rather than failing mid-way.
   */
  unavailableReason(): string | undefined {
    const c = this.config;
    if (c.provider === 'none') {
      return 'no AI provider configured (CODELENS_AI_PROVIDER=none). Deterministic analysis ran in full; AI semantic investigation was not attempted.';
    }
    if (!c.model) return `no model configured for provider '${c.provider}' (set CODELENS_AI_MODEL)`;
    if ((c.provider === 'anthropic' || c.provider === 'openai')) {
      if (!c.apiKey) {
        return `provider '${c.provider}' is selected but no API key is set. Refusing to proceed.`;
      }
      if (!c.externalTransferAcknowledged) {
        return `provider '${c.provider}' would send repository content to a third party. Set CODELENS_AI_ACCEPT_EXTERNAL_TRANSFER=true to acknowledge this before enabling it.`;
      }
    }
    return undefined;
  }

  async complete(req: ModelRequest): Promise<ModelResponse> {
    const reason = this.unavailableReason();
    if (reason) throw new ProviderDisabled(reason);

    const projected = estimateTokens(req.system) + estimateTokens(req.user) + (req.maxOutputTokens ?? 1024);
    if (this.spent + projected > this.config.tokenBudget) {
      throw new BudgetExceeded(this.spent + projected, this.config.tokenBudget);
    }

    const res = await this.dispatch(req);
    this.spentIn += res.tokensIn;
    this.spentOut += res.tokensOut;
    this.requests++;
    return res;
  }

  private async dispatch(req: ModelRequest): Promise<ModelResponse> {
    switch (this.config.provider) {
      case 'ollama': return this.ollama(req);
      case 'anthropic': return this.anthropic(req);
      case 'openai': return this.openai(req);
      default: throw new ProviderDisabled('no provider');
    }
  }

  private async ollama(req: ModelRequest): Promise<ModelResponse> {
    const body = {
      model: this.config.model,
      stream: false,
      options: { temperature: req.temperature ?? 0, num_predict: req.maxOutputTokens ?? 1024 },
      messages: [
        { role: 'system', content: req.system },
        { role: 'user', content: req.user },
      ],
      ...(req.schema ? { format: req.schema } : {}),
    };
    const res = await fetch(`${this.config.ollamaUrl}/api/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(180_000),
    });
    if (!res.ok) {
      throw new Error(`Ollama responded ${res.status}: ${(await res.text()).slice(0, 300)}`);
    }
    const j = (await res.json()) as {
      message?: { content?: string };
      prompt_eval_count?: number;
      eval_count?: number;
    };
    return {
      text: j.message?.content ?? '',
      tokensIn: j.prompt_eval_count ?? estimateTokens(req.system + req.user),
      tokensOut: j.eval_count ?? 0,
      model: this.config.model,
      provider: 'ollama',
    };
  }

  private async anthropic(req: ModelRequest): Promise<ModelResponse> {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': this.config.apiKey!,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.config.model,
        max_tokens: req.maxOutputTokens ?? 1024,
        temperature: req.temperature ?? 0,
        system: req.system,
        messages: [{ role: 'user', content: req.user }],
      }),
      signal: AbortSignal.timeout(180_000),
    });
    if (!res.ok) {
      throw new Error(`Anthropic API responded ${res.status}: ${(await res.text()).slice(0, 300)}`);
    }
    const j = (await res.json()) as {
      content?: Array<{ text?: string }>;
      usage?: { input_tokens?: number; output_tokens?: number };
    };
    return {
      text: j.content?.map((c) => c.text ?? '').join('') ?? '',
      tokensIn: j.usage?.input_tokens ?? 0,
      tokensOut: j.usage?.output_tokens ?? 0,
      model: this.config.model,
      provider: 'anthropic',
    };
  }

  private async openai(req: ModelRequest): Promise<ModelResponse> {
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${this.config.apiKey!}`,
      },
      body: JSON.stringify({
        model: this.config.model,
        temperature: req.temperature ?? 0,
        max_tokens: req.maxOutputTokens ?? 1024,
        messages: [
          { role: 'system', content: req.system },
          { role: 'user', content: req.user },
        ],
        ...(req.schema ? { response_format: { type: 'json_object' } } : {}),
      }),
      signal: AbortSignal.timeout(180_000),
    });
    if (!res.ok) {
      throw new Error(`OpenAI API responded ${res.status}: ${(await res.text()).slice(0, 300)}`);
    }
    const j = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
      usage?: { prompt_tokens?: number; completion_tokens?: number };
    };
    return {
      text: j.choices?.[0]?.message?.content ?? '',
      tokensIn: j.usage?.prompt_tokens ?? 0,
      tokensOut: j.usage?.completion_tokens ?? 0,
      model: this.config.model,
      provider: 'openai',
    };
  }
}
