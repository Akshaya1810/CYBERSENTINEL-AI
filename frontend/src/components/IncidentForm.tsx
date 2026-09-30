import { useState, type FormEvent } from 'react'
import { api } from '../services/api'
import type { Incident, IncidentCreateInput, IncidentSeverity } from '../types'

const severities: IncidentSeverity[] = ['Critical', 'High', 'Medium', 'Low']

interface IncidentFormProps {
  onCreated: (incident: Incident) => void
  onCancel: () => void
}

export function IncidentForm({ onCreated, onCancel }: IncidentFormProps) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setBusy(true)
    const form = new FormData(event.currentTarget)
    const sourceIp = String(form.get('source_ip') ?? '').trim()
    const input: IncidentCreateInput = {
      title: String(form.get('title') ?? '').trim(),
      description: String(form.get('description') ?? '').trim(),
      severity: String(form.get('severity') ?? 'Medium') as IncidentSeverity,
      ...(sourceIp ? { source_ip: sourceIp } : {}),
    }
    try {
      onCreated(await api.createIncident(input))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Incident could not be created.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onCancel()}>
      <section className="dialog" role="dialog" aria-modal="true" aria-labelledby="create-title">
        <div className="dialog-heading"><div><span className="eyebrow">INCIDENT MANAGEMENT</span><h2 id="create-title">Create incident</h2><p>Record an incident in your local database.</p></div><button className="close-button" onClick={onCancel} aria-label="Close">×</button></div>
        <form className="form-grid" onSubmit={submit}>
          <label className="field full">Title<input name="title" required maxLength={200} autoFocus placeholder="Short incident summary" /></label>
          <label className="field full">Description<textarea name="description" rows={4} placeholder="What has been observed?" /></label>
          <label className="field">Severity<select name="severity" defaultValue="Medium">{severities.map((value) => <option key={value}>{value}</option>)}</select></label>
          <label className="field">Source IP <span className="field-hint">Optional</span><input name="source_ip" maxLength={45} placeholder="e.g. 192.0.2.10" /></label>
          {error && <p className="form-error full" role="alert">{error}</p>}
          <div className="form-actions full"><button type="button" className="button-secondary" onClick={onCancel}>Cancel</button><button className="button-primary" disabled={busy}>{busy ? 'Saving…' : 'Create incident'}</button></div>
        </form>
      </section>
    </div>
  )
}
