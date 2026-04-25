// aiProviders.js — Multi-provider AI adapter for the analyzer.
//
// Supports:
//   - openai          (https://api.openai.com/v1)
//   - openai-compat   (any OpenAI-compatible endpoint, set baseURL)
//   - anthropic       (https://api.anthropic.com/v1, Claude)
//   - google          (https://generativelanguage.googleapis.com/v1beta, Gemini)
//   - groq            (https://api.groq.com/openai/v1)
//   - openrouter      (https://openrouter.ai/api/v1)
//   - xai             (https://api.x.ai/v1, Grok)
//   - mistral         (https://api.mistral.ai/v1)
//   - deepseek        (https://api.deepseek.com/v1)
//   - ollama          (http://localhost:11434, OFFLINE local models)
//   - lmstudio        (http://localhost:1234/v1, OFFLINE local models)
//
// Two functions exported:
//   chat(opts)        -> { ok, text, model, error }
//   listModels(opts)  -> { ok, models:[{id, label}], error }

const PRESETS = {
  openai:      { baseURL: 'https://api.openai.com/v1',                     auth: 'bearer', api: 'openai',     defaultModel: 'gpt-4o-mini' },
  'openai-compat': { baseURL: '',                                          auth: 'bearer', api: 'openai',     defaultModel: '' },
  anthropic:   { baseURL: 'https://api.anthropic.com/v1',                  auth: 'x-api-key', api: 'anthropic', defaultModel: 'claude-3-5-sonnet-latest' },
  google:      { baseURL: 'https://generativelanguage.googleapis.com/v1beta', auth: 'query', api: 'google',  defaultModel: 'gemini-2.0-flash' },
  groq:        { baseURL: 'https://api.groq.com/openai/v1',                auth: 'bearer', api: 'openai',     defaultModel: 'llama-3.3-70b-versatile' },
  openrouter:  { baseURL: 'https://openrouter.ai/api/v1',                  auth: 'bearer', api: 'openai',     defaultModel: 'openai/gpt-4o-mini' },
  xai:         { baseURL: 'https://api.x.ai/v1',                           auth: 'bearer', api: 'openai',     defaultModel: 'grok-2-latest' },
  mistral:     { baseURL: 'https://api.mistral.ai/v1',                     auth: 'bearer', api: 'openai',     defaultModel: 'mistral-large-latest' },
  deepseek:    { baseURL: 'https://api.deepseek.com/v1',                   auth: 'bearer', api: 'openai',     defaultModel: 'deepseek-chat' },
  ollama:      { baseURL: 'http://127.0.0.1:11434',                        auth: 'none',   api: 'ollama',     defaultModel: 'llama3.2' },
  lmstudio:    { baseURL: 'http://127.0.0.1:1234/v1',                      auth: 'none',   api: 'openai',     defaultModel: '' },
};

function resolve(opts = {}) {
  const provider = (opts.provider || 'openai').toLowerCase();
  const preset = PRESETS[provider] || PRESETS.openai;
  return {
    provider,
    api: preset.api,
    baseURL: (opts.baseURL || preset.baseURL || '').replace(/\/$/, ''),
    auth: preset.auth,
    apiKey: opts.apiKey || '',
    model: opts.model || preset.defaultModel,
    timeoutMs: opts.timeoutMs || 90_000,
  };
}

async function fetchWithTimeout(url, init, ms) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try { return await fetch(url, { ...init, signal: ctl.signal }); }
  finally { clearTimeout(t); }
}

// ─── chat() ───
async function chat(opts) {
  const c = resolve(opts);
  if (!c.baseURL) return { error: 'baseURL trống — cần cấu hình provider hoặc nhập baseURL.' };
  if (!c.model)   return { error: 'model trống — chọn model trước khi gọi.' };

  const sys  = opts.system || 'You are a helpful assistant.';
  const user = opts.user   || '';
  const temperature = typeof opts.temperature === 'number' ? opts.temperature : 0.3;
  const maxTokens   = opts.maxTokens || 2048;

  try {
    if (c.api === 'openai') {
      // OpenAI-compatible: /chat/completions
      const headers = { 'Content-Type': 'application/json' };
      if (c.auth === 'bearer' && c.apiKey) headers.Authorization = 'Bearer ' + c.apiKey;
      // OpenRouter site headers (optional but recommended)
      if (c.provider === 'openrouter') {
        headers['HTTP-Referer'] = opts.referer || 'http://localhost';
        headers['X-Title']      = opts.title   || 'proxy-checker analyzer';
      }
      // GPT-5 / o1 / o3 / o4 reasoning families on OpenAI:
      //   - reject `max_tokens`     → must use `max_completion_tokens`
      //   - reject custom `temperature` (only default=1 supported)
      //   - tiêu hao token cho reasoning nội bộ trước khi sinh text → cần budget lớn hơn
      const m = (c.model || '').toLowerCase();
      const isReasoning = c.provider === 'openai' && /^(gpt-5|o1|o3|o4)/.test(m);
      const body = {
        model: c.model,
        messages: [
          { role: 'system', content: sys },
          { role: 'user',   content: user },
        ],
      };
      if (isReasoning) {
        // reasoning model — đảm bảo có đủ ngân sách cho reasoning + visible output.
        // OpenAI khuyến nghị tối thiểu vài nghìn token; ta đặt sàn 16k để tránh trả rỗng.
        body.max_completion_tokens = Math.max(maxTokens, 16384);
      } else {
        body.max_tokens  = maxTokens;
        body.temperature = temperature;
      }
      const r = await fetchWithTimeout(c.baseURL + '/chat/completions', {
        method: 'POST', headers, body: JSON.stringify(body),
      }, c.timeoutMs);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) return { error: j.error?.message || j.error || ('HTTP ' + r.status), raw: j };
      const choice = j.choices?.[0] || {};
      const text   = choice.message?.content;
      if (!text) {
        const finish = choice.finish_reason || 'unknown';
        const used   = j.usage?.completion_tokens || 0;
        const reasoning = j.usage?.completion_tokens_details?.reasoning_tokens || 0;
        let hint = '';
        if (finish === 'length') {
          hint = isReasoning
            ? ` Reasoning model "${c.model}" đã tiêu hết ngân sách token cho reasoning (${reasoning}/${used}) trước khi sinh text. Tăng "Max tokens" trong request hoặc giảm độ dài system prompt / scope.`
            : ` Vượt giới hạn max_tokens (${used}). Tăng max_tokens hoặc giảm scope.`;
        } else if (finish === 'content_filter') {
          hint = ' Bị filter nội dung của OpenAI.';
        }
        return { error: `AI trả về rỗng (finish_reason=${finish}).${hint}`, raw: j };
      }
      return { ok: true, text, model: c.model, provider: c.provider, usage: j.usage };
    }

    if (c.api === 'anthropic') {
      // Anthropic /messages
      const headers = {
        'Content-Type': 'application/json',
        'x-api-key': c.apiKey,
        'anthropic-version': '2023-06-01',
      };
      const body = {
        model: c.model,
        max_tokens: maxTokens,
        temperature,
        system: sys,
        messages: [{ role: 'user', content: user }],
      };
      const r = await fetchWithTimeout(c.baseURL + '/messages', {
        method: 'POST', headers, body: JSON.stringify(body),
      }, c.timeoutMs);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) return { error: j.error?.message || ('HTTP ' + r.status), raw: j };
      const text = (j.content || []).map(p => p.text || '').join('').trim();
      if (!text) return { error: 'AI trả về rỗng', raw: j };
      return { ok: true, text, model: c.model, provider: c.provider, usage: j.usage };
    }

    if (c.api === 'google') {
      // Gemini: POST /models/<model>:generateContent?key=...
      const url = `${c.baseURL}/models/${encodeURIComponent(c.model)}:generateContent?key=${encodeURIComponent(c.apiKey)}`;
      const body = {
        systemInstruction: { parts: [{ text: sys }] },
        contents: [{ role: 'user', parts: [{ text: user }] }],
        generationConfig: { temperature, maxOutputTokens: maxTokens },
      };
      const r = await fetchWithTimeout(url, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      }, c.timeoutMs);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) return { error: j.error?.message || ('HTTP ' + r.status), raw: j };
      const text = (j.candidates?.[0]?.content?.parts || []).map(p => p.text || '').join('').trim();
      if (!text) return { error: 'AI trả về rỗng', raw: j };
      return { ok: true, text, model: c.model, provider: c.provider };
    }

    if (c.api === 'ollama') {
      // Ollama /api/chat (offline)
      const body = {
        model: c.model,
        stream: false,
        options: { temperature, num_predict: maxTokens },
        messages: [
          { role: 'system', content: sys },
          { role: 'user',   content: user },
        ],
      };
      const r = await fetchWithTimeout(c.baseURL + '/api/chat', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      }, c.timeoutMs);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) return { error: j.error || ('HTTP ' + r.status), raw: j };
      const text = j.message?.content || '';
      if (!text) return { error: 'AI trả về rỗng', raw: j };
      return { ok: true, text, model: c.model, provider: c.provider };
    }

    return { error: 'Provider api không hỗ trợ: ' + c.api };
  } catch (e) {
    if (e.name === 'AbortError') return { error: 'Timeout sau ' + (c.timeoutMs/1000) + 's' };
    return { error: 'Call failed: ' + e.message };
  }
}

// ─── listModels() ───
async function listModels(opts) {
  const c = resolve(opts);
  if (!c.baseURL) return { error: 'baseURL trống' };
  try {
    if (c.api === 'openai') {
      // OpenAI-compatible /models
      const headers = {};
      if (c.auth === 'bearer' && c.apiKey) headers.Authorization = 'Bearer ' + c.apiKey;
      const r = await fetchWithTimeout(c.baseURL + '/models', { headers }, 15_000);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) return { error: j.error?.message || ('HTTP ' + r.status), raw: j };
      const arr = j.data || j.models || [];
      const models = arr.map(m => ({ id: m.id || m.name, label: m.id || m.name })).filter(m => m.id);
      return { ok: true, models };
    }
    if (c.api === 'anthropic') {
      const headers = { 'x-api-key': c.apiKey, 'anthropic-version': '2023-06-01' };
      const r = await fetchWithTimeout(c.baseURL + '/models', { headers }, 15_000);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) return { error: j.error?.message || ('HTTP ' + r.status), raw: j };
      const models = (j.data || []).map(m => ({ id: m.id, label: m.display_name || m.id }));
      return { ok: true, models };
    }
    if (c.api === 'google') {
      const r = await fetchWithTimeout(c.baseURL + '/models?key=' + encodeURIComponent(c.apiKey), {}, 15_000);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) return { error: j.error?.message || ('HTTP ' + r.status), raw: j };
      const models = (j.models || [])
        .filter(m => (m.supportedGenerationMethods || []).includes('generateContent'))
        .map(m => ({ id: m.name.replace(/^models\//, ''), label: m.displayName || m.name }));
      return { ok: true, models };
    }
    if (c.api === 'ollama') {
      const r = await fetchWithTimeout(c.baseURL + '/api/tags', {}, 10_000);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) return { error: j.error || ('HTTP ' + r.status), raw: j };
      const models = (j.models || []).map(m => ({ id: m.name, label: m.name + ' (' + (m.details?.parameter_size || '') + ')' }));
      return { ok: true, models };
    }
    return { error: 'listModels chưa hỗ trợ provider: ' + c.api };
  } catch (e) {
    if (e.name === 'AbortError') return { error: 'Timeout' };
    return { error: e.message };
  }
}

// ─── Auto model selection ───
// Tier table: từ "fast/cheap" → "balanced" → "deep reasoning". autoSelectModel()
// chọn tier dựa trên input-token estimate + cờ wantReasoning.
//   - small  : ≤ ~30k input tokens, không cần reasoning → fast model
//   - medium : 30k–120k tokens hoặc balanced
//   - large  : > 120k tokens hoặc wantReasoning=true → deep / large-context
const MODEL_TIERS = {
  openai:        { fast: 'gpt-4o-mini',        balanced: 'gpt-4o',         deep: 'gpt-5.5' },
  'openai-compat':{fast: '',                   balanced: '',               deep: '' },
  anthropic:     { fast: 'claude-3-5-haiku-latest', balanced: 'claude-3-5-sonnet-latest', deep: 'claude-3-7-sonnet-latest' },
  google:        { fast: 'gemini-2.0-flash',   balanced: 'gemini-2.5-flash', deep: 'gemini-2.5-pro' },
  groq:          { fast: 'llama-3.1-8b-instant', balanced: 'llama-3.3-70b-versatile', deep: 'llama-3.3-70b-versatile' },
  openrouter:    { fast: 'openai/gpt-4o-mini', balanced: 'openai/gpt-4o',  deep: 'anthropic/claude-3.5-sonnet' },
  xai:           { fast: 'grok-2-latest',      balanced: 'grok-2-latest',  deep: 'grok-2-latest' },
  mistral:       { fast: 'mistral-small-latest', balanced: 'mistral-large-latest', deep: 'mistral-large-latest' },
  deepseek:      { fast: 'deepseek-chat',      balanced: 'deepseek-chat',  deep: 'deepseek-reasoner' },
  ollama:        { fast: 'llama3.2',           balanced: 'llama3.1:8b',    deep: 'deepseek-r1:8b' },
  lmstudio:      { fast: '',                   balanced: '',               deep: '' },
};

function estimateTokens(text) {
  return Math.ceil((text || '').length / 4); // rough: ~4 chars/token English, ~3 cho VN có dấu
}

// Trả về { model, tier, reason }
function autoSelectModel(opts = {}) {
  const provider = (opts.provider || 'openai').toLowerCase();
  const tiers = MODEL_TIERS[provider] || MODEL_TIERS.openai;
  const inTok = estimateTokens(opts.system) + estimateTokens(opts.user);
  const want  = opts.wantReasoning ? 'deep' : (inTok > 120_000 ? 'deep' : inTok > 30_000 ? 'balanced' : 'fast');
  const model = tiers[want] || tiers.balanced || tiers.fast || PRESETS[provider]?.defaultModel || '';
  return {
    model, tier: want,
    reason: `~${inTok.toLocaleString()} input tokens, ${opts.wantReasoning ? 'reasoning ON' : 'reasoning OFF'} → ${want}`,
  };
}

// ─── chatStream() — SSE streaming ───
// Gọi onEvent(ev) với:
//   { type:'meta',    model, provider }
//   { type:'thinking',delta }   (Anthropic extended thinking, Ollama <think>)
//   { type:'text',    delta }
//   { type:'usage',   usage }
//   { type:'done' }
//   { type:'error',   error }
// Tr\u1ea3 v\u1ec1 promise resolve khi xong.
async function chatStream(opts, onEvent) {
  const c = resolve(opts);
  if (!c.baseURL) { onEvent({ type:'error', error:'baseURL trống' }); return; }
  if (!c.model)   { onEvent({ type:'error', error:'model trống' }); return; }

  const sys  = opts.system || 'You are a helpful assistant.';
  const user = opts.user   || '';
  const temperature = typeof opts.temperature === 'number' ? opts.temperature : 0.3;
  const maxTokens   = opts.maxTokens || 4096;
  const showThinking = !!opts.showThinking;

  onEvent({ type:'meta', model: c.model, provider: c.provider });

  try {
    if (c.api === 'openai') {
      const headers = { 'Content-Type':'application/json', 'Accept':'text/event-stream' };
      if (c.auth === 'bearer' && c.apiKey) headers.Authorization = 'Bearer ' + c.apiKey;
      if (c.provider === 'openrouter') {
        headers['HTTP-Referer'] = opts.referer || 'http://localhost';
        headers['X-Title']      = opts.title   || 'proxy-checker analyzer';
      }
      const m = (c.model || '').toLowerCase();
      const isReasoning = c.provider === 'openai' && /^(gpt-5|o1|o3|o4)/.test(m);
      const body = {
        model: c.model, stream: true,
        messages: [{ role:'system', content:sys }, { role:'user', content:user }],
      };
      if (isReasoning) body.max_completion_tokens = Math.max(maxTokens, 16384);
      else { body.max_tokens = maxTokens; body.temperature = temperature; }

      const r = await fetchWithTimeout(c.baseURL + '/chat/completions',
        { method:'POST', headers, body: JSON.stringify(body) }, c.timeoutMs);
      if (!r.ok || !r.body) {
        const txt = await r.text().catch(()=>''); 
        onEvent({ type:'error', error: 'HTTP ' + r.status + ': ' + txt.slice(0,200) }); return;
      }
      await consumeSSE(r.body, (data) => {
        if (data === '[DONE]') return;
        let j; try { j = JSON.parse(data); } catch(_) { return; }
        const delta = j.choices?.[0]?.delta?.content;
        if (delta) onEvent({ type:'text', delta });
        if (j.usage) onEvent({ type:'usage', usage: j.usage });
      });
      if (isReasoning && showThinking) {
        onEvent({ type:'note', text: '⚠ OpenAI Chat Completions không stream reasoning visibility cho model gpt-5/o-series. Để xem suy nghĩ, dùng Anthropic (Claude 3.7+) hoặc Ollama deepseek-r1/qwq.' });
      }
      onEvent({ type:'done' });
      return;
    }

    if (c.api === 'anthropic') {
      const headers = {
        'Content-Type':'application/json', 'Accept':'text/event-stream',
        'x-api-key': c.apiKey, 'anthropic-version':'2023-06-01',
      };
      const body = {
        model: c.model, stream: true, max_tokens: Math.max(maxTokens, 4096),
        temperature, system: sys,
        messages: [{ role:'user', content:user }],
      };
      // Extended thinking (Claude 3.7+ / claude-opus-4 / sonnet 4)
      if (showThinking && /claude-(3-7|opus-4|sonnet-4|3\.7)/i.test(c.model)) {
        body.thinking = { type:'enabled', budget_tokens: Math.max(2048, Math.floor(maxTokens/2)) };
        delete body.temperature; // thinking yêu cầu temp default
      }
      const r = await fetchWithTimeout(c.baseURL + '/messages',
        { method:'POST', headers, body: JSON.stringify(body) }, c.timeoutMs);
      if (!r.ok || !r.body) {
        const txt = await r.text().catch(()=>'');
        onEvent({ type:'error', error: 'HTTP ' + r.status + ': ' + txt.slice(0,200) }); return;
      }
      await consumeSSE(r.body, (data) => {
        let j; try { j = JSON.parse(data); } catch(_) { return; }
        if (j.type === 'content_block_delta') {
          const d = j.delta || {};
          if (d.type === 'text_delta'     && d.text)     onEvent({ type:'text',     delta: d.text });
          if (d.type === 'thinking_delta' && d.thinking) onEvent({ type:'thinking', delta: d.thinking });
        } else if (j.type === 'message_delta' && j.usage) {
          onEvent({ type:'usage', usage: j.usage });
        } else if (j.type === 'error') {
          onEvent({ type:'error', error: j.error?.message || 'anthropic error' });
        }
      });
      onEvent({ type:'done' });
      return;
    }

    if (c.api === 'google') {
      // Gemini streamGenerateContent SSE
      const url = `${c.baseURL}/models/${encodeURIComponent(c.model)}:streamGenerateContent?alt=sse&key=${encodeURIComponent(c.apiKey)}`;
      const body = {
        systemInstruction: { parts:[{ text: sys }] },
        contents: [{ role:'user', parts:[{ text: user }] }],
        generationConfig: { temperature, maxOutputTokens: maxTokens },
      };
      const r = await fetchWithTimeout(url,
        { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) }, c.timeoutMs);
      if (!r.ok || !r.body) {
        const txt = await r.text().catch(()=>'');
        onEvent({ type:'error', error: 'HTTP ' + r.status + ': ' + txt.slice(0,200) }); return;
      }
      await consumeSSE(r.body, (data) => {
        let j; try { j = JSON.parse(data); } catch(_) { return; }
        const parts = j.candidates?.[0]?.content?.parts || [];
        for (const p of parts) {
          if (p.text) onEvent({ type: p.thought ? 'thinking' : 'text', delta: p.text });
        }
        if (j.usageMetadata) onEvent({ type:'usage', usage: j.usageMetadata });
      });
      onEvent({ type:'done' });
      return;
    }

    if (c.api === 'ollama') {
      // Ollama /api/chat — JSONL streaming. Một số reasoning model (deepseek-r1, qwq)
      // sinh ra thẻ <think>...</think> nội tuyến → tách ra event 'thinking'.
      const body = {
        model: c.model, stream: true,
        options: { temperature, num_predict: maxTokens },
        messages: [{ role:'system', content:sys }, { role:'user', content:user }],
      };
      const r = await fetchWithTimeout(c.baseURL + '/api/chat',
        { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) }, c.timeoutMs);
      if (!r.ok || !r.body) {
        const txt = await r.text().catch(()=>'');
        onEvent({ type:'error', error: 'HTTP ' + r.status + ': ' + txt.slice(0,200) }); return;
      }
      let inThink = false;
      await consumeJSONL(r.body, (j) => {
        const piece = j.message?.content || '';
        if (!piece) return;
        // tách <think> ... </think>
        let buf = piece;
        while (buf.length) {
          if (!inThink) {
            const i = buf.indexOf('<think>');
            if (i < 0) { onEvent({ type:'text', delta: buf }); break; }
            if (i > 0) onEvent({ type:'text', delta: buf.slice(0, i) });
            buf = buf.slice(i + 7); inThink = true;
          } else {
            const i = buf.indexOf('</think>');
            if (i < 0) { onEvent({ type:'thinking', delta: buf }); break; }
            if (i > 0) onEvent({ type:'thinking', delta: buf.slice(0, i) });
            buf = buf.slice(i + 8); inThink = false;
          }
        }
        if (j.done && j.eval_count) onEvent({ type:'usage', usage:{ output_tokens:j.eval_count, input_tokens:j.prompt_eval_count } });
      });
      onEvent({ type:'done' });
      return;
    }

    onEvent({ type:'error', error: 'Streaming chưa hỗ trợ provider api: ' + c.api });
  } catch (e) {
    onEvent({ type:'error', error: e.name === 'AbortError' ? 'Timeout' : e.message });
  }
}

// ─── helpers: SSE & JSONL stream readers ───
async function consumeSSE(stream, onData) {
  const reader = stream.getReader(); const dec = new TextDecoder(); let buf = '';
  while (true) {
    const { value, done } = await reader.read(); if (done) break;
    buf += dec.decode(value, { stream:true });
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).replace(/\r$/, ''); buf = buf.slice(idx + 1);
      if (line.startsWith('data: ')) onData(line.slice(6).trim());
      else if (line.startsWith('data:')) onData(line.slice(5).trim());
    }
  }
  if (buf.startsWith('data: ')) onData(buf.slice(6).trim());
}
async function consumeJSONL(stream, onObj) {
  const reader = stream.getReader(); const dec = new TextDecoder(); let buf = '';
  while (true) {
    const { value, done } = await reader.read(); if (done) break;
    buf += dec.decode(value, { stream:true });
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).trim(); buf = buf.slice(idx + 1);
      if (!line) continue;
      try { onObj(JSON.parse(line)); } catch(_) {}
    }
  }
  if (buf.trim()) { try { onObj(JSON.parse(buf)); } catch(_){} }
}

module.exports = { chat, chatStream, listModels, PRESETS, MODEL_TIERS, autoSelectModel, estimateTokens };
