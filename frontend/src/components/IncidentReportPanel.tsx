import { useCallback, useEffect, useState } from 'react'
import { api } from '../services/api'
import type { IncidentReport, InvestigationRun } from '../types'

const dateTime = (value: string | null) => value ? new Date(value).toLocaleString() : 'Timestamp unknown'
interface Props { incidentId: number }

export function IncidentReportPanel({ incidentId }: Props) {
  const [report, setReport] = useState<IncidentReport | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [downloading, setDownloading] = useState(false)
  const [investigating, setInvestigating] = useState(false)
  const [latestRun, setLatestRun] = useState<InvestigationRun | null>(null)
  const load = useCallback(async () => {
    setLoading(true); setError('')
    try { setReport(await api.getIncidentReport(incidentId)) }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Incident report could not be loaded.') }
    finally { setLoading(false) }
  }, [incidentId])
  useEffect(() => { void load() }, [load])

  async function download() {
    setDownloading(true); setError('')
    try {
      const url = URL.createObjectURL(await api.downloadIncidentReport(incidentId))
      const anchor = document.createElement('a')
      anchor.href = url; anchor.download = `incident-${incidentId}-report.md`; anchor.click()
      URL.revokeObjectURL(url)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Report download failed.') }
    finally { setDownloading(false) }
  }

  async function investigate() {
    setInvestigating(true); setError(''); setLatestRun(null)
    try {
      const result = await api.runIncidentInvestigation(incidentId)
      setLatestRun(result)
      if (result.status === 'completed') await load()
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Local Ollama investigation could not be started.') }
    finally { setInvestigating(false) }
  }

  const savedRuns = report?.ai_investigations ?? []
  const investigationRuns = latestRun?.status === 'completed'
    ? [...savedRuns.filter((run) => run.investigation_result_id !== latestRun.investigation_result_id), latestRun]
    : savedRuns

  return <section className="report-panel" aria-label="Structured incident report">
    <div className="panel-heading"><div><h3>Incident report</h3><p>Evidence, independent verification, and possible ATT&amp;CK mappings</p></div>
      <div className="report-actions"><button className="button-primary" disabled={loading || investigating || !report} onClick={() => void investigate()}>{investigating ? 'Investigating with local Ollama…' : 'Run local investigation'}</button><button className="button-secondary" disabled={loading || downloading || !report} onClick={() => void download()}>{downloading ? 'Preparing…' : 'Download Markdown'}</button></div>
    </div>
    {loading ? <div className="mini-state">Loading report…</div> : error ? <div className="notice-error" role="alert">{error}<button className="text-button" onClick={() => void load()}>Retry</button></div> : report && <>
      <div className="report-status"><strong>Verification: {report.verification.status.replaceAll('_', ' ')}</strong><span>{report.timeline.length} evidence events</span></div>
      <section className="report-block"><h4>Evidence timeline</h4>
        {report.timeline.length ? <ol className="report-timeline">{report.timeline.map((event) => <li key={event.id}><time>{dateTime(event.timestamp)}</time><strong>#{event.id} · {event.event_type}</strong><p>{event.description}</p><small>{event.source_ip ?? 'Source IP unknown'}{event.username ? ` · ${event.username}` : ''}</small></li>)}</ol> : <p className="muted-empty">No security-event evidence is available.</p>}
        <p className="report-entities"><strong>Source IPs:</strong> {report.source_ips.join(', ') || 'Unknown'} · <strong>Affected accounts:</strong> {report.affected_accounts.join(', ') || 'Unknown'}</p>
      </section>
      <section className="report-block"><h4>MITRE ATT&amp;CK references</h4>
        {report.attack_mappings.length ? report.attack_mappings.map((item) => <article className="report-card" key={item.technique_id}><a href={item.source_url} target="_blank" rel="noreferrer">{item.technique_id} · {item.name}</a><p>{item.qualification}</p></article>) : <p className="muted-empty">No evidence-qualified technique mapping.</p>}
      </section>
      <section className="report-block"><h4>Verification and warnings</h4>
        <p>{report.verification.supported_claims.length} supported · {report.verification.unsupported_claims.length} unsupported or unverified</p>
        {report.verification.unsupported_claims.map((claim, index) => <article className="report-card warning" key={`${claim.text}-${index}`}><strong>{claim.status}: {claim.text}</strong><small>{claim.reasons.join(' ')}</small></article>)}
        {report.verification.warnings.map((warning, index) => <p className="report-warning" key={index}>{warning}</p>)}
        {!report.verification.warnings.length && !report.verification.unsupported_claims.length && <p className="report-ok">No unsupported structured claims found.</p>}
      </section>
      <section className="report-block"><h4>Local Ollama investigation</h4>
        {latestRun && latestRun.status !== 'completed' && <div className="notice-error" role="alert">Investigation {latestRun.status}: {latestRun.error_message ?? 'No model output was accepted.'} Inference used: {latestRun.inference_used ? 'yes' : 'no'}.</div>}
        {investigationRuns.length ? investigationRuns.map((run, runIndex) => <article className="report-card ollama-result" key={run.investigation_result_id ?? runIndex}>
          <div className="event-title"><strong>Ollama · {run.model}</strong><span className={`badge status ${run.inference_used ? 'resolved' : 'closed'}`}>{run.inference_used ? 'Inference used' : run.status}</span></div>
          {run.analysis?.summary && <p><strong>Concise model interpretation:</strong> {run.analysis.summary} · evidence IDs: {run.analysis.summary_event_ids.join(', ')}</p>}
          <p><strong>Triage:</strong> {run.analysis?.triage.summary}</p><small>Uncertainty: {run.analysis?.triage.uncertainty} · event IDs: {run.analysis?.triage.event_ids.join(', ') || 'none'}</small>
          <strong>Investigation findings</strong>
          {run.analysis?.findings.length ? run.analysis.findings.map((finding, index) => <p key={index}>[{finding.classification}] {finding.text} · evidence IDs: {finding.event_ids.join(', ') || 'none'}</p>) : <p>No structured findings returned.</p>}
          <strong>Attack reconstruction hypothesis</strong><p>{run.analysis?.attack_reconstruction.summary}</p><small>{run.analysis?.attack_reconstruction.uncertainty} · evidence IDs: {run.analysis?.attack_reconstruction.event_ids.join(', ') || 'none'}</small>
          <strong>Impact and risk</strong><p>Risk: {run.analysis?.risk_assessment.level} — {run.analysis?.risk_assessment.rationale}</p><small>Risk uncertainty: {run.analysis?.risk_assessment.uncertainty}</small>
          <p>Observed impact: {run.analysis?.impact_assessment.observed.map((item) => item.text).join('; ') || 'None established.'}</p><p>Potential impact: {run.analysis?.impact_assessment.potential.map((item) => item.text).join('; ') || 'Not stated.'}</p>
          <strong>Advisory response recommendations</strong>
          {run.analysis?.response_recommendations.length ? run.analysis.response_recommendations.map((item, index) => <p key={index}>{item.text} · {item.action_type} · approval required · evidence IDs: {item.event_ids.join(', ') || 'none'}</p>) : <p>No recommendation returned.</p>}
          <strong>Independent verification: {run.verification?.status ?? 'unavailable'}</strong>
          {run.verification?.warnings.map((warning, index) => <p className="report-warning" key={index}>{warning}</p>)}
          {run.verification?.unsupported_claims.map((claim, index) => <small key={index}>Unverified/unsupported: {claim.text} ({claim.status})</small>)}
          <details><summary>Pipeline responsibilities</summary><ul>{run.modules.map((module) => <li key={module.module}>{module.module}: {module.method} · {module.status} — {module.responsibility}</li>)}</ul></details>
        </article>) : !latestRun && <p className="muted-empty">No Ollama investigation has been run for this incident. Run local Ollama to generate one; deterministic detection and reporting continue independently.</p>}
      </section>
      <section className="report-block"><h4>Saved findings and response</h4>
        {report.investigation_findings.length ? report.investigation_findings.map((finding) => <article className="report-card" key={finding.id}><strong>{finding.agent_name} · {finding.verification}</strong><p>{finding.findings}</p></article>) : <p className="muted-empty">No investigation findings recorded.</p>}
        {report.response_recommendations.length ? report.response_recommendations.map((item, index) => <p className="report-card" key={index}>{item.text} · approval: {item.approval_status}</p>) : <p className="muted-empty">No response recommendations recorded; approval status unavailable.</p>}
      </section>
      <details className="report-json"><summary>View structured report JSON</summary><pre>{JSON.stringify(report, null, 2)}</pre></details>
      <ul className="report-limitations">{report.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul>
    </>}
  </section>
}
