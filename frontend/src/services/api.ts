import type {
  DatabaseHealth,
  DetectionHistoryItem,
  DetectionRule,
  HealthStatus,
  Incident,
  IncidentReport,
  InvestigationRun,
  IncidentCreateInput,
  IncidentDetail,
  IncidentUpdateInput,
  LogUploadSummary,
  InvestigationResult,
  InvestigationResultCreateInput,
  SecurityEvent,
  SecurityEventCreateInput,
} from '../types'

const API_BASE_URL = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000').replace(/\/+$/, '')

export class ApiError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message)
    this.name = 'ApiError'
  }
}

function getErrorMessage(payload: unknown, status: number): string {
  if (payload && typeof payload === 'object' && 'detail' in payload) {
    const detail = (payload as { detail: unknown }).detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail)) {
      return detail.map((item) => {
        if (!item || typeof item !== 'object') return 'Invalid request.'
        const issue = item as { loc?: unknown[]; msg?: string }
        const field = issue.loc?.filter((part) => part !== 'body').join('.')
        return field ? `${field}: ${issue.msg ?? 'Invalid value.'}` : issue.msg ?? 'Invalid request.'
      }).join(' ')
    }
  }
  if (status === 404) return 'The requested incident was not found.'
  return `The backend request failed (HTTP ${status}).`
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body !== undefined && !(init.body instanceof FormData)) headers.set('Content-Type', 'application/json')

  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers })
  } catch {
    throw new ApiError('Cannot reach the local backend. Check that FastAPI is running.', 0)
  }

  if (response.status === 204) return undefined as T
  const responseText = await response.text()
  let payload: unknown = null
  if (responseText) {
    try { payload = JSON.parse(responseText) as unknown } catch { payload = null }
  }
  if (!response.ok) throw new ApiError(getErrorMessage(payload, response.status), response.status)
  return payload as T
}

export const api = {
  getHealth: () => request<HealthStatus>('/api/health'),
  getDatabaseHealth: () => request<DatabaseHealth>('/api/db-health'),
  listIncidents: () => request<Incident[]>('/api/incidents'),
  getIncident: (id: number) => request<IncidentDetail>(`/api/incidents/${id}`),
  createIncident: (input: IncidentCreateInput) =>
    request<Incident>('/api/incidents', { method: 'POST', body: JSON.stringify(input) }),
  updateIncident: (id: number, input: IncidentUpdateInput) =>
    request<Incident>(`/api/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(input) }),
  deleteIncident: (id: number) => request<void>(`/api/incidents/${id}`, { method: 'DELETE' }),
  listSecurityEvents: (incidentId: number) =>
    request<SecurityEvent[]>(`/api/incidents/${incidentId}/events`),
  createSecurityEvent: (incidentId: number, input: SecurityEventCreateInput) =>
    request<SecurityEvent>(`/api/incidents/${incidentId}/events`, {
      method: 'POST', body: JSON.stringify(input),
    }),
  createInvestigationResult: (incidentId: number, input: InvestigationResultCreateInput) =>
    request<InvestigationResult>(`/api/incidents/${incidentId}/investigation-results`, {
      method: 'POST', body: JSON.stringify(input),
    }),
  uploadSecurityLog: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return request<LogUploadSummary>('/api/logs/upload', { method: 'POST', body: form })
  },
  listDetectionRules: () => request<DetectionRule[]>('/api/detections/rules'),
  listDetectionHistory: () => request<DetectionHistoryItem[]>('/api/detections/history'),
  getIncidentReport: (id: number) => request<IncidentReport>(`/api/incidents/${id}/report`),
  runIncidentInvestigation: (id: number) => request<InvestigationRun>(`/api/incidents/${id}/investigate`, { method: 'POST' }),
  downloadIncidentReport: async (id: number): Promise<Blob> => {
    let response: Response
    try { response = await fetch(`${API_BASE_URL}/api/incidents/${id}/report.md`) }
    catch { throw new ApiError('Cannot reach the local backend. Check that FastAPI is running.', 0) }
    if (!response.ok) {
      const body = await response.json().catch(() => null) as unknown
      throw new ApiError(getErrorMessage(body, response.status), response.status)
    }
    return response.blob()
  },
}
