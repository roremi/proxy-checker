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
        body.max_completion_tokens = maxTokens;
      } else {
        body.max_tokens  = maxTokens;
        body.temperature = temperature;
      }
      const r = await fetchWithTimeout(c.baseURL + '/chat/completions', {
        method: 'POST', headers, body: JSON.stringify(body),
      }, c.timeoutMs);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) return { error: j.error?.message || j.error || ('HTTP ' + r.status), raw: j };
      const text = j.choices?.[0]?.message?.content;
      if (!text) return { error: 'AI trả về rỗng', raw: j };
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

module.exports = { chat, listModels, PRESETS };
