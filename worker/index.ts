interface D1RunResult {
  success?: boolean
  meta?: { changes?: number }
}

interface D1Statement {
  bind(...values: Array<string | number | null>): D1Statement
  run(): Promise<D1RunResult>
}

interface D1Database {
  prepare(query: string): D1Statement
}

interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>
}

interface WorkerEnv {
  ASSETS: { fetch(request: Request): Promise<Response> }
  LEADS_DB: D1Database
  LEADS_RATE_LIMITER: RateLimitBinding
  TURNSTILE_SECRET: string
  SITE_ORIGIN: string
}

interface LeadPayload {
  name?: unknown
  email?: unknown
  organization?: unknown
  projectType?: unknown
  timeline?: unknown
  details?: unknown
  consent?: unknown
  turnstileToken?: unknown
  website?: unknown
}

const MAX_BODY_BYTES = 8_000
const MAX_DETAILS_LENGTH = 2_000
const projectTypes = new Set([
  'Site ou aplicação web',
  'Sistema ou plataforma',
  'API ou integração',
  'Automação',
  'Outro',
])
const timelines = new Set(['', 'Nas próximas semanas', 'Nos próximos meses', 'Sem prazo definido'])

function json(body: Record<string, unknown>, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  })
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function cleanText(value: unknown): string | null {
  if (typeof value !== 'string') return null
  return value.trim()
}

async function readBoundedBody(request: Request): Promise<string | null> {
  const reader = request.body?.getReader()
  if (!reader) return ''

  const chunks: Uint8Array[] = []
  let totalBytes = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      totalBytes += value.byteLength
      if (totalBytes > MAX_BODY_BYTES) {
        await reader.cancel()
        return null
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }

  const body = new Uint8Array(totalBytes)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder().decode(body)
}

async function verifyTurnstile(token: string, ip: string, env: WorkerEnv, expectedHost: string): Promise<boolean> {
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      secret: env.TURNSTILE_SECRET,
      response: token,
      remoteip: ip,
      idempotency_key: crypto.randomUUID(),
    }),
  })

  if (!response.ok) return false
  const result: unknown = await response.json()
  if (!isRecord(result)) return false

  return result.success === true && result.hostname === expectedHost && result.action === 'lead_submit'
}

async function createLead(request: Request, env: WorkerEnv): Promise<Response> {
  const origin = request.headers.get('Origin')
  let siteOrigin: URL
  try {
    siteOrigin = new URL(env.SITE_ORIGIN)
  } catch {
    return json({ error: 'service_unavailable' }, 503)
  }

  const requestHost = new URL(request.url).hostname
  const isLocalWorker = requestHost === 'localhost' || requestHost === '127.0.0.1'
  const localOrigins = new Set(['http://localhost:5173', 'http://127.0.0.1:5173'])
  if (origin !== siteOrigin.origin && !(isLocalWorker && origin && localOrigins.has(origin))) {
    return json({ error: 'forbidden' }, 403)
  }
  if (request.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json') {
    return json({ error: 'unsupported_media_type' }, 415)
  }

  const ip = request.headers.get('CF-Connecting-IP') ?? (isLocalWorker ? '127.0.0.1' : null)
  if (!ip) return json({ error: 'forbidden' }, 403)

  const rateLimit = await env.LEADS_RATE_LIMITER.limit({ key: ip })
  if (!rateLimit.success) return json({ error: 'rate_limited' }, 429)

  const declaredLength = Number(request.headers.get('Content-Length') ?? 0)
  if (declaredLength > MAX_BODY_BYTES) return json({ error: 'payload_too_large' }, 413)

  const bodyText = await readBoundedBody(request)
  if (bodyText === null) return json({ error: 'payload_too_large' }, 413)

  let body: unknown
  try {
    body = JSON.parse(bodyText)
  } catch {
    return json({ error: 'invalid_payload' }, 400)
  }
  if (!isRecord(body)) return json({ error: 'invalid_payload' }, 400)

  const payload = body as LeadPayload
  // Honeypot: silently discard automated submissions without revealing the trap.
  if (typeof payload.website === 'string' && payload.website.trim()) {
    return json({ ok: true }, 202)
  }

  const name = cleanText(payload.name)
  const email = cleanText(payload.email)?.toLowerCase() ?? null
  const organization = cleanText(payload.organization)
  const projectType = cleanText(payload.projectType)
  const timeline = cleanText(payload.timeline)
  const details = cleanText(payload.details)
  const token = cleanText(payload.turnstileToken)

  if (
    !name || name.length > 120 ||
    !email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    (organization !== null && organization.length > 160) ||
    !projectType || !projectTypes.has(projectType) ||
    timeline === null || !timelines.has(timeline) ||
    !details || details.length < 20 || details.length > MAX_DETAILS_LENGTH ||
    payload.consent !== true
  ) {
    return json({ error: 'invalid_fields' }, 400)
  }

  if (!env.TURNSTILE_SECRET || !token || token.length > 2_048) {
    return json({ error: 'verification_required' }, 400)
  }

  try {
    const verified = await verifyTurnstile(token, ip, env, siteOrigin.hostname)
    if (!verified) return json({ error: 'verification_failed' }, 400)
  } catch {
    return json({ error: 'verification_unavailable' }, 503)
  }

  const id = crypto.randomUUID()
  try {
    const result = await env.LEADS_DB.prepare(
      `INSERT INTO leads (id, name, email, organization, project_type, timeline, details)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(id, name, email, organization || null, projectType, timeline || null, details).run()

    if (result.success === false) throw new Error('D1 insert failed')
  } catch {
    return json({ error: 'storage_unavailable' }, 503)
  }

  return json({ ok: true, requestId: id }, 201)
}

export default {
  async fetch(request: Request, env: WorkerEnv): Promise<Response> {
    const url = new URL(request.url)
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request)
    if (url.pathname !== '/api/leads') return json({ error: 'not_found' }, 404)
    if (request.method !== 'POST') {
      return new Response(null, { status: 405, headers: { Allow: 'POST' } })
    }

    try {
      return await createLead(request, env)
    } catch {
      return json({ error: 'internal_error' }, 500)
    }
  },
}
