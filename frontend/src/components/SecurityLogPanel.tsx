import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api } from '../services/api'
import type { DetectionHistoryItem, DetectionRule, LogUploadSummary } from '../types'

const dateTime = (value: string) => new Date(value).toLocaleString()
const windowLabel = (seconds: number) => seconds % 60 ? `${seconds}s` : `${seconds / 60} min`

interface SecurityLogPanelProps {
  onUploadCompleted: () => void
  onOpenIncident: (incidentId: number) => void
}

export function SecurityLogPanel({ onUploadCompleted, onOpenIncident }: SecurityLogPanelProps) {
  const [rules, setRules] = useState<DetectionRule[]>([])
  const [history, setHistory] = useState<DetectionHistoryItem[]>([])
  const [loading, setLoading] = useState(true)
  const [historyError, setHistoryError] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState('')
  const [summary, setSummary] = useState<LogUploadSummary | null>(null)

  const refreshDetectionData = useCallback(async () => {
    setHistoryError('')
    const [ruleResult, historyResult] = await Promise.allSettled([
      api.listDetectionRules(), api.listDetectionHistory(),
    ])
    if (ruleResult.status === 'fulfilled') setRules(ruleResult.value)
    else setHistoryError(ruleResult.reason instanceof Error ? ruleResult.reason.message : 'Detection rules could not be loaded.')
    if (historyResult.status === 'fulfilled') setHistory(historyResult.value)
    else setHistoryError(historyResult.reason instanceof Error ? historyResult.reason.message : 'Detection history could not be loaded.')
    setLoading(false)
  }, [])

  useEffect(() => { void refreshDetectionData() }, [refreshDetectionData])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!file) return
    const formElement = event.currentTarget
    setUploading(true)
    setUploadError('')
    setSummary(null)
    try {
      const result = await api.uploadSecurityLog(file)
      setSummary(result)
      setFile(null)
      formElement.reset()
      onUploadCompleted()
      await refreshDetectionData()
    } catch (cause) {
      setUploadError(cause instanceof Error ? cause.message : 'The log file could not be processed.')
    } finally {
      setUploading(false)
    }
  }

  return (
    <section className="panel log-workspace" id="log-ingestion">
      <div className="panel-heading"><div><h2>Security log ingestion</h2><p>Parse local log files and evaluate deterministic rules</p></div><span className="phase-pill">LOCAL ONLY</span></div>
      <div className="log-grid">
        <div className="upload-column">
          <form className="upload-form" onSubmit={submit}>
            <label className="field">Linux SSH log or CSV file<input type="file" accept=".log,.txt,.csv,text/plain,text/csv" required onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></label>
            <p className="upload-help">UTF-8 .log/.txt or .csv · up to 5 MiB and 10,000 records · uploaded files are parsed as data, never executed.</p>
            <button className="button-primary" disabled={!file || uploading}>{uploading ? <><span className="spinner small-spinner"/> Processing log…</> : 'Upload and analyze'}</button>
          </form>
          <div className="csv-help"><strong>CSV columns</strong><p>Use headers such as <code>timestamp</code>, <code>event_type</code>, <code>source_ip</code>, <code>username</code>, <code>hostname</code>, <code>description</code>, and <code>raw_log</code>. Header capitalization and common name variations are accepted.</p></div>
          {uploadError && <div className="notice-error upload-error" role="alert">{uploadError}</div>}
          {summary && <div className="upload-summary" role="status"><div className="summary-heading"><strong>Processed {summary.filename}</strong><span>{summary.file_format.toUpperCase()}</span></div><div className="summary-stats"><div><strong>{summary.processed_records}</strong><small>processed</small></div><div><strong>{summary.rejected_records}</strong><small>rejected</small></div><div><strong>{summary.detections.length}</strong><small>detections</small></div></div>
            {!summary.detections.length && <p className="summary-note">No configured rule triggered for these records. Unrecognized records are not classified as threats.</p>}
            {summary.detections.map((detection, index) => <article className="upload-detection" key={`${detection.rule_id}-${detection.id ?? index}`}><div className="event-title"><span className={`badge severity ${detection.severity.toLowerCase()}`}>{detection.severity}</span><button className="text-button" onClick={() => onOpenIncident(detection.incident_id)}>Open incident #{detection.incident_id} ↗</button></div><strong>{detection.rule_name}</strong><p>{detection.description}</p><small>Evidence event IDs: {detection.event_ids.join(', ')}</small></article>)}
            {!!summary.malformed_records.length && <details className="issue-list"><summary>Malformed records ({summary.rejected_records})</summary>{summary.malformed_records.map((issue, index) => <p key={`${issue.record_number}-${index}`}>Record {issue.record_number}: {issue.reason}</p>)}</details>}
            {!!summary.warning_count && <details className="issue-list"><summary>Normalization notes ({summary.warning_count})</summary>{summary.warnings.map((warning, index) => <p key={index}>{warning}</p>)}{summary.warning_count > summary.warnings.length && <p>Additional notes omitted from this response.</p>}</details>}
          </div>}
        </div>
        <div className="rule-column"><div className="panel-heading"><div><h3>Active detection rules</h3><p>Configured thresholds from the backend</p></div></div>
          {loading ? <div className="mini-state">Loading rule configuration…</div> : rules.length ? <div className="rule-list">{rules.map((rule) => <article className="rule-item" key={rule.rule_id}><div className="event-title"><strong>{rule.name}</strong><span className={`badge severity ${rule.severity.toLowerCase()}`}>{rule.severity}</span></div><div className="rule-meta"><code>{rule.rule_id}</code><strong>{rule.threshold} events / {windowLabel(rule.window_seconds)}</strong></div><p>{rule.description}</p></article>)}</div> : <div className="mini-state">No active rules returned.</div>}
        </div>
      </div>
      <div className="history-section"><div className="panel-heading"><div><h3>Recent detection history</h3><p>Persisted rule matches and linked incidents</p></div><button className="text-button" onClick={() => void refreshDetectionData()} disabled={loading}>↻ Refresh</button></div>
        {historyError && <p className="form-error" role="alert">{historyError}</p>}
        {loading ? <div className="mini-state">Loading detection history…</div> : history.length ? <div className="history-list">{history.map((item) => <article className="history-item" key={item.id}><div className="event-title"><div><span className={`badge severity ${item.severity.toLowerCase()}`}>{item.severity}</span><strong>{item.rule_name}</strong></div><time>{dateTime(item.detected_at)}</time></div><p>{item.description}</p><div className="history-meta"><span>{item.source_ip}</span><span>{item.event_ids.length} evidence events</span><button className="text-button" onClick={() => onOpenIncident(item.incident_id)}>Incident #{item.incident_id} ↗</button></div></article>)}</div> : <div className="mini-state">No detections have been recorded.</div>}
      </div>
    </section>
  )
}
