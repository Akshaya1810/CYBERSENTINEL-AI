import { useCallback, useEffect, useMemo, useState } from 'react'
import { IncidentDetails } from './components/IncidentDetails'
import { IncidentForm } from './components/IncidentForm'
import { SecurityLogPanel } from './components/SecurityLogPanel'
import { api } from './services/api'
import type { DatabaseHealth, HealthStatus, Incident, IncidentSeverity, IncidentStatus } from './types'

type Connection = 'checking' | 'connected' | 'unavailable'
const severityOrder: IncidentSeverity[] = ['Critical', 'High', 'Medium', 'Low']
const statusOrder: IncidentStatus[] = ['Open', 'Investigating', 'Resolved', 'Closed']
const dateTime = (value: string) => new Date(value).toLocaleString()

function App() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [loadError, setLoadError] = useState('')
  const [apiStatus, setApiStatus] = useState<Connection>('checking')
  const [dbStatus, setDbStatus] = useState<Connection>('checking')
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [databaseHealth, setDatabaseHealth] = useState<DatabaseHealth | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null)
  const [activeNav, setActiveNav] = useState('overview')
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null)

  const refreshDashboard = useCallback(async (showLoading = false) => {
    if (showLoading) setLoading(true)
    else setRefreshing(true)
    setLoadError('')
    const [incidentResult, apiResult, dbResult] = await Promise.allSettled([
      api.listIncidents(), api.getHealth(), api.getDatabaseHealth(),
    ])
    if (incidentResult.status === 'fulfilled') setIncidents(incidentResult.value)
    else setLoadError(incidentResult.reason instanceof Error ? incidentResult.reason.message : 'Incidents could not be loaded.')
    if (apiResult.status === 'fulfilled') { setHealth(apiResult.value); setApiStatus('connected') }
    else { setHealth(null); setApiStatus('unavailable') }
    if (dbResult.status === 'fulfilled' && dbResult.value.database === 'connected') { setDatabaseHealth(dbResult.value); setDbStatus('connected') }
    else { setDatabaseHealth(null); setDbStatus('unavailable') }
    setLastRefreshed(new Date())
    setLoading(false)
    setRefreshing(false)
  }, [])

  useEffect(() => { void refreshDashboard(true) }, [refreshDashboard])

  const severityCounts = useMemo(() => Object.fromEntries(
    severityOrder.map((severity) => [severity, incidents.filter((incident) => incident.severity === severity).length]),
  ) as Record<IncidentSeverity, number>, [incidents])
  const statusCounts = useMemo(() => Object.fromEntries(
    statusOrder.map((status) => [status, incidents.filter((incident) => incident.status === status).length]),
  ) as Record<IncidentStatus, number>, [incidents])

  function created(incident: Incident) {
    setCreateOpen(false)
    setSelectedIncidentId(incident.id)
    void refreshDashboard()
  }

  function deleted() {
    setSelectedIncidentId(null)
    void refreshDashboard()
  }

  return (
    <main className="shell">
      <aside className="sidebar">
        <a className="brand" href="#overview" onClick={() => setActiveNav('overview')}><span className="brand-mark">C</span><span>Cyber<span className="brand-accent">Sentinel</span><small>AI SECURITY OPERATIONS</small></span></a>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          <a className={`nav-item ${activeNav === 'overview' ? 'active' : ''}`} href="#overview" onClick={() => setActiveNav('overview')}><span>◫</span> Overview</a>
          <a className={`nav-item ${activeNav === 'incidents' ? 'active' : ''}`} href="#incidents" onClick={() => setActiveNav('incidents')}><span>⌁</span> Incidents <i>{incidents.length}</i></a>
          <a className={`nav-item ${activeNav === 'investigations' ? 'active' : ''}`} href="#investigations" onClick={() => setActiveNav('investigations')}><span>◎</span> Investigations</a>
          <a className={`nav-item ${activeNav === 'logs' ? 'active' : ''}`} href="#log-ingestion" onClick={() => setActiveNav('logs')}><span>⇧</span> Log ingestion</a>
          <a className="nav-item muted" href="#agents"><span>◇</span> Agents <i className="soon">SOON</i></a>
          <a className="nav-item muted" href="#privacy"><span>⚙</span> Settings</a>
        </nav>
        <div className="sidebar-bottom"><div className="local-card"><span className="local-dot"/><div><strong>Local environment</strong><small>Data stays on this machine</small></div></div><div className="profile"><div className="avatar">CS</div><div><strong>Security Analyst</strong><small>Local workspace</small></div><span className="profile-menu">···</span></div></div>
      </aside>
      <section className="content" id="overview">
        <header className="topbar"><div className="crumb">Workspace <span>/</span> <strong>Overview</strong></div><div className="top-actions"><span className="environment"><span/> LOCAL DEV</span><div className="avatar small">CS</div></div></header>
        <div className="page">
          <div className="heading"><div><div className="eyebrow">SECURITY OPERATIONS CENTER <span className="live-dot"/> LOCAL DATA</div><h1>Security overview</h1><p>Review and manage incidents stored in your local PostgreSQL database.</p></div><div className="heading-actions"><button className="button-secondary refresh-button" onClick={() => void refreshDashboard()} disabled={refreshing}>{refreshing ? 'Refreshing…' : '↻ Refresh'}</button><button className="button-primary" onClick={() => setCreateOpen(true)}>＋ New incident</button></div></div>
          <div className="banner"><div className="banner-icon">⌘</div><div className="banner-copy"><strong>{dbStatus === 'connected' ? 'Local incident data connected' : 'Local-first incident workspace'}</strong><p>{dbStatus === 'connected' ? 'Incident records are loaded from the FastAPI backend and PostgreSQL.' : 'Incident data is loaded from your local backend. Automated security analysis is not running.'}</p></div><span className="phase-pill">LOCAL</span></div>
          {loadError && <div className="notice-error" role="alert"><span>{loadError}</span><button className="text-button" onClick={() => void refreshDashboard(true)}>Retry</button></div>}
          <div className="section-heading"><div><h2>System overview</h2><p>Live status and counts based on stored incident records</p></div><span className="updated"><span className={`live-dot ${apiStatus === 'unavailable' ? 'offline' : ''}`}/> {lastRefreshed ? `UPDATED ${lastRefreshed.toLocaleTimeString()}` : 'LOADING STATUS'}</span></div>
          <div className="metrics">
            <article className="metric-card"><div className="metric-top"><span>Backend API</span><span className="metric-icon blue">⌘</span></div><div className="metric-value status-value"><span className={`status-dot ${apiStatus}`}/>{apiStatus === 'checking' ? 'Checking' : apiStatus === 'connected' ? 'Connected' : 'Unavailable'}</div><div className="metric-foot">{health ? `${health.service ?? 'FastAPI'} · ${health.status}` : apiStatus === 'unavailable' ? 'Start FastAPI to connect' : 'Checking local health endpoint'}</div></article>
            <article className="metric-card"><div className="metric-top"><span>PostgreSQL</span><span className="metric-icon violet">▤</span></div><div className="metric-value status-value"><span className={`status-dot ${dbStatus}`}/>{dbStatus === 'checking' ? 'Checking' : dbStatus === 'connected' ? 'Connected' : 'Unavailable'}</div><div className="metric-foot">{databaseHealth?.database ?? (dbStatus === 'unavailable' ? 'Check the backend database connection' : 'Local database health')}</div></article>
            <article className="metric-card"><div className="metric-top"><span>Total incidents</span><span className="metric-icon cyan">⌁</span></div><div className="metric-value">{loading ? '—' : incidents.length}</div><div className="metric-foot">Stored incidents in this workspace</div></article>
            <article className="metric-card"><div className="metric-top"><span>Critical incidents</span><span className="metric-icon amber">!</span></div><div className="metric-value">{loading ? '—' : severityCounts.Critical}</div><div className="metric-foot">Counted from current incident records</div></article>
          </div>
          <div className="lower-grid breakdown-grid">
            <article className="panel"><div className="panel-heading"><div><h2>By severity</h2><p>Incident distribution from API data</p></div></div><div className="count-list">{severityOrder.map((severity) => <div className="count-row" key={severity}><span className={`badge severity ${severity.toLowerCase()}`}>{severity}</span><span className="count-track"><span className={`count-fill ${severity.toLowerCase()}`} style={{ width: incidents.length ? `${(severityCounts[severity] / incidents.length) * 100}%` : '0%' }}/></span><strong>{loading ? '—' : severityCounts[severity]}</strong></div>)}</div></article>
            <article className="panel"><div className="panel-heading"><div><h2>By status</h2><p>Current workflow state</p></div></div><div className="count-list">{statusOrder.map((status) => <div className="count-row" key={status}><span className={`badge status ${status.toLowerCase()}`}>{status}</span><span className="count-track"><span className={`count-fill ${status.toLowerCase()}`} style={{ width: incidents.length ? `${(statusCounts[status] / incidents.length) * 100}%` : '0%' }}/></span><strong>{loading ? '—' : statusCounts[status]}</strong></div>)}</div></article>
          </div>
          <section className="panel incident-panel" id="incidents"><div className="panel-heading"><div><h2>Incident queue</h2><p>Newest incidents first · select a record to view details</p></div><span className="step-count">{incidents.length} TOTAL</span></div>
            {loading ? <div className="table-state" role="status"><span className="spinner"/> Loading incidents from the backend…</div> : loadError && incidents.length === 0 ? <div className="table-state">Incident data is unavailable. Check that the backend is running, then retry.</div> : incidents.length === 0 ? <div className="empty-state"><span className="empty-icon">⌁</span><h3>No incidents yet</h3><p>Create an incident to begin tracking records in your local workspace.</p><button className="button-primary" onClick={() => setCreateOpen(true)}>＋ Create first incident</button></div> : <div className="table-wrap"><table><thead><tr><th>INCIDENT</th><th>SEVERITY</th><th>STATUS</th><th>SOURCE IP</th><th>CREATED</th><th/></tr></thead><tbody>{incidents.map((incident) => <tr key={incident.id}><td><button className="incident-link" onClick={() => setSelectedIncidentId(incident.id)}><strong>{incident.title}</strong><small>INC-{String(incident.id).padStart(4, '0')}</small></button></td><td><span className={`badge severity ${incident.severity.toLowerCase()}`}>{incident.severity}</span></td><td><span className={`badge status ${incident.status.toLowerCase()}`}>{incident.status}</span></td><td className="mono-cell">{incident.source_ip || '—'}</td><td className="date-cell">{dateTime(incident.created_at)}</td><td><button className="row-action" onClick={() => setSelectedIncidentId(incident.id)}>Details <span>›</span></button></td></tr>)}</tbody></table></div>}
          </section>
          <SecurityLogPanel onUploadCompleted={() => void refreshDashboard()} onOpenIncident={(id) => setSelectedIncidentId(id)} />
          <div className="lower-grid bottom-grid">
            <article className="panel" id="investigations"><div className="panel-heading"><div><h2>Investigation records</h2><p>Saved results are shown inside their incident details</p></div><span className="metric-icon cyan">◎</span></div><div className="info-empty">{incidents.length ? 'Select an incident above to review its saved findings and confidence values.' : 'Investigation results will appear here through their incident records when available.'}</div></article>
            <article className="panel" id="agents"><div className="panel-heading"><div><h2>AI orchestration</h2><p>Future local workflow</p></div><span className="metric-icon violet">◇</span></div><div className="info-empty">No agents are running. Investigation results displayed in this dashboard are records saved through the API.</div></article>
          </div>
          <article className="panel privacy-panel privacy-bottom" id="privacy"><div className="panel-heading"><div><h2>Privacy by design</h2><p>Local-first project configuration</p></div><span className="shield">⬡</span></div><div className="privacy-list"><div><span className="privacy-check">✓</span><span>Uses a local backend connection</span></div><div><span className="privacy-check">✓</span><span>No external AI API configured</span></div><div><span className="privacy-check">✓</span><span>No secrets included in the frontend</span></div></div><div className="privacy-note">No cloud AI services or external incident data sources are configured.</div></article>
          <footer>CYBERSENTINEL AI <span>·</span> LOCAL DEVELOPMENT <span>·</span> INCIDENT MANAGEMENT</footer>
        </div>
      </section>
      {createOpen && <IncidentForm onCancel={() => setCreateOpen(false)} onCreated={created} />}
      {selectedIncidentId !== null && <IncidentDetails incidentId={selectedIncidentId} onClose={() => setSelectedIncidentId(null)} onChanged={() => void refreshDashboard()} onDeleted={deleted} />}
    </main>
  )
}

export default App
