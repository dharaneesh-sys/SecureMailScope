export class ApiError extends Error {
  status: number
  code?: string
  constructor(status: number, message: string, code?: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

function detailMessage(d: unknown): { message: string; code?: string } {
  if (typeof d === 'string') return { message: d }
  if (Array.isArray(d)) return { message: d.map((x) => (typeof x === 'object' && x && 'msg' in x ? String((x as { msg: unknown }).msg) : String(x))).join('; ') }
  if (d && typeof d === 'object') {
    const o = d as { message?: string; code?: string }
    return { message: o.message ?? JSON.stringify(d), code: o.code }
  }
  return { message: 'Request failed' }
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const isForm = init.body instanceof FormData
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: { ...(init.body && !isForm ? { 'Content-Type': 'application/json' } : {}), ...init.headers },
  })
  if (!res.ok) {
    let body: { detail?: unknown } = {}
    try { body = await res.json() } catch { /* non-JSON error body */ }
    const { message, code } = detailMessage(body.detail)
    throw new ApiError(res.status, message || `${res.status} ${res.statusText}`, code)
  }
  return (res.status === 204 ? undefined : await res.json()) as T
}

export const get = <T,>(path: string) => request<T>(path)
export const post = <T,>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })
export const patch = <T,>(path: string, body: unknown) => request<T>(path, { method: 'PATCH', body: JSON.stringify(body) })
export const put = <T,>(path: string, body: unknown) => request<T>(path, { method: 'PUT', body: JSON.stringify(body) })
export const del = <T,>(path: string) => request<T>(path, { method: 'DELETE' })

export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') u.set(k, String(v))
  const s = u.toString()
  return s ? `?${s}` : ''
}

/** Upload with progress (fetch cannot report upload progress, XHR can). */
export function uploadCapture(file: File, onProgress: (pct: number) => void): Promise<import('@/types/api').UploadResult> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', '/api/captures')
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((100 * e.loaded) / e.total))
    xhr.onload = () => {
      let body: any = {}
      try { body = JSON.parse(xhr.responseText) } catch { /* ignore */ }
      if (xhr.status >= 200 && xhr.status < 300) return resolve(body)
      const { message, code } = detailMessage(body.detail)
      reject(new ApiError(xhr.status, message || `Upload failed (${xhr.status})`, code))
    }
    xhr.onerror = () => reject(new ApiError(0, 'Could not reach the SecureMailScope backend (is it running on http://localhost:8000?)'))
    const fd = new FormData()
    fd.append('file', file)
    xhr.send(fd)
  })
}
