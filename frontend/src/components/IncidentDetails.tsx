import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api } from '../services/api'
import type { IncidentDetail as IncidentDetailType, IncidentSeverity, IncidentStatus } from '../types'
import { IncidentReportPanel } from './IncidentReportPanel'

const severities: IncidentSeverity[] = ['Critical', 'High', 'Medium', 'Low']
const statuses: IncidentStatus[] = ['Open', 'Investigating', 'Resolved', 'Closed']
const dateTime = (value: string | null) => value ? new Date(value).toLocaleString() : 'Timestamp unavailable'

interface IncidentDetailsProps {
  incidentId: number
  onClose: () => void
  onChanged: () => void
  onDeleted: () => void
}

export function IncidentDetails({ incidentId, onClose, onChanged, onDeleted }: IncidentDetailsProps) {
  const [incident, setIncident] = useState<IncidentDetailType | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [severity, setSeverity] = useState<IncidentSeverity>('Medium')
  const [status, setStatus] = useState<IncidentStatus>('Open')
  const [eventError, setEventError] = useState('')
  const [eventBusy, setEventBusy] = useState(false)

  const loadIncident = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const result = await api.getIncident(incidentId)
      setIncident(result)
      setSeverity(result.severity)
      setStatus(result.status)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Incident details could not be loaded.')
    } finally {
      setLoading(false)
    }
  }, [incidentId])

  useEffect(() => { void loadIncident() }, [loadIncident])

  async function update(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await api.updateIncident(incidentId, { severity, status })
      setNotice('Incident updated.')
      await loadIncident()
      onChanged()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Incident could not be updated.')
    } finally {
      setBusy(false)
    }
  }

  async function removeIncident() {
    if (!incident || !window.confirm(`Delete “${incident.title}” and its related events and results?`)) return
    setBusy(true)
    setError('')
    try {
      await api.deleteIncident(incidentId)
      onDeleted()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Incident could not be deleted.')
      setBusy(false)
    }
  }

  async function addEvent(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setEventError('')
    setEventBusy(true)
    const formElement = event.currentTarget
    const form = new FormData(formElement)
    const sourceIp = String(form.get('source_ip') ?? '').trim()
    const rawLog = String(form.get('raw_log') ?? '').trim()
    try {
      await api.createSecurityEvent(incidentId, {
        event_type: String(form.get('event_type') ?? '').trim(),
        description: String(form.get('description') ?? '').trim(),
        ...(sourceIp ? { source_ip: sourceIp } : {}),
        ...(rawLog ? { raw_log: rawLog } : {}),
      })
      formElement.reset()
      await loadIncident()
      onChanged()
    } catch (cause) {
      setEventError(cause instanceof Error ? cause.message : 'Security event could not be added.')
    } finally {
      setEventBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section className="dialog dialog-wide" role="dialog" aria-modal="true" aria-labelledby="detail-title">
        <div className="dialog-heading"><div><span className="eyebrow">INCIDENT {incident ? `#${incident.id}` : ''}</span><h2 id="detail-title">{incident?.title ?? 'Incident details'}</h2><p>{incident ? `Created ${dateTime(incident.created_at)}` : 'Loading incident information'}</p></div><button className="close-button" onClick={onClose} aria-label="Close">×</button></div>
        {loading ? <div className="dialog-loading" role="status">Loading incident details…</div> : error && !incident ? <div className="error-state" role="alert">{error}<button className="button-secondary" onClick={() => void loadIncident()}>Retry</button></div> : incident && <>
          {error && <p className="form-error" role="alert">{error}</p>}{notice && <p className="success-message" role="status">{notice}</p>}
          <div className="detail-summary"><div><span className="detail-label">Severity</span><span className={`badge severity ${incident.severity.toLowerCase()}`}>{incident.severity}</span></div><div><span className="detail-label">Status</span><span className={`badge status ${incident.status.toLowerCase()}`}>{incident.status}</span></div><div><span className="detail-label">Source IP</span><strong>{incident.source_ip || '—'}</strong></div><div><span className="detail-label">Last updated</span><strong>{dateTime(incident.updated_at)}</strong></div></div>
          {incident.description && <p className="detail-description">{incident.description}</p>}
          <form className="inline-update" onSubmit={update}><label className="field">Severity<select value={severity} onChange={(event) => setSeverity(event.target.value as IncidentSeverity)}>{severities.map((item) => <option key={item}>{item}</option>)}</select></label><label className="field">Status<select value={status} onChange={(event) => setStatus(event.target.value as IncidentStatus)}>{statuses.map((item) => <option key={item}>{item}</option>)}</select></label><button className="button-primary" disabled={busy}>{busy ? 'Saving…' : 'Save changes'}</button><button type="button" className="button-danger" disabled={busy} onClick={() => void removeIncident()}>Delete incident</button></form>
          <div className="detail-columns">
            <section className="detail-section"><div className="panel-heading"><div><h3>Security events <span className="count-chip">{incident.security_events.length}</span></h3><p>Events recorded for this incident</p></div></div>
              {incident.security_events.length ? <div className="event-list">{incident.security_events.map((item) => <article className="event-item" key={item.id}><div className="event-title"><strong>{item.event_type}</strong><time>{dateTime(item.timestamp)}</time></div><p>{item.description}</p>{item.source_ip && <small>Source IP · {item.source_ip}</small>}{item.username && <small>Username · {item.username}</small>}{item.hostname && <small>Hostname · {item.hostname}</small>}{item.raw_log && <pre>{item.raw_log}</pre>}</article>)}</div> : <p className="muted-empty">No security events recorded.</p>}
              <form className="event-form" onSubmit={addEvent}><h4>Add security event</h4><label className="field">Event type<input name="event_type" required maxLength={100} placeholder="e.g. authentication_failure" /></label><label className="field">Description<textarea name="description" required rows={2} placeholder="What happened?" /></label><div className="form-grid compact"><label className="field">Source IP <span className="field-hint">Optional</span><input name="source_ip" maxLength={45} /></label><label className="field">Raw log <span className="field-hint">Optional</span><textarea name="raw_log" rows={2} /></label></div>{eventError && <p className="form-error" role="alert">{eventError}</p>}<button className="button-secondary" disabled={eventBusy}>{eventBusy ? 'Adding…' : 'Add event'}</button></form>
            </section>
            <section className="detail-section" id="investigations"><div className="panel-heading"><div><h3>Investigation results <span className="count-chip">{incident.investigation_results.length}</span></h3><p>Saved findings associated with this incident</p></div></div>
              {incident.investigation_results.length ? <div className="result-list">{incident.investigation_results.map((item) => <article className="result-item" key={item.id}><div className="event-title"><strong>{item.agent_name}</strong><time>{dateTime(item.created_at)}</time></div><p>{item.findings}</p><small>Confidence · {item.confidence === null ? 'Not provided' : `${Math.round(item.confidence * 100)}%`}</small></article>)}</div> : <p className="muted-empty">No investigation results have been saved for this incident.</p>}
              <div className="privacy-note">These are stored investigation records. Automated AI analysis is not active.</div>
            </section>
          </div>
          <IncidentReportPanel incidentId={incident.id} />
        </>}
      </section>
    </div>
  )
}
