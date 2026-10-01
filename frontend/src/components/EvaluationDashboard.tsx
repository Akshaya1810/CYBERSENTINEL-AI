import { useEffect, useState } from 'react'
import { ApiError, api } from '../services/api'
import type { EvaluationMetric, EvaluationResults } from '../types'

const metricCards = [
  ['detection_precision', 'Detection precision'],
  ['detection_recall', 'Detection recall'],
  ['detection_f1', 'Detection F1'],
  ['false_positive_rate', 'False-positive rate'],
  ['attack_mapping_exact_case_accuracy', 'ATT&CK mapping accuracy'],
  ['severity_risk_category_accuracy', 'Risk category accuracy'],
  ['expected_evidence_coverage', 'Evidence coverage'],
  ['verification_supported_claim_rate', 'Supported verifier probes'],
  ['unsupported_claim_detection_rate', 'Unsupported-claim detection'],
  ['response_recommendation_safety_compliance', 'Response safety compliance'],
] as const

const modeLabels: Record<string, string> = {
  deterministic_baseline: 'Deterministic baseline',
  complete_pipeline: 'Complete CyberSentinel pipeline',
}

function isMetric(value: unknown): value is EvaluationMetric {
  return Boolean(
    value && typeof value === 'object' && 'value' in value
    && 'numerator' in value && 'denominator' in value,
  )
}

function metricDisplay(metric: EvaluationMetric | undefined): string {
  if (!metric || metric.value === null || !Number.isFinite(metric.value)) return 'Unavailable'
  return `${(metric.value * 100).toFixed(1)}%`
}

export function EvaluationDashboard() {
  const [results, setResults] = useState<EvaluationResults | null>(null)
  const [selectedMode, setSelectedMode] = useState('')
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<{ message: string; missing: boolean } | null>(null)

  async function loadResults() {
    setLoading(true)
    setLoadError(null)
    try {
      const payload = await api.getEvaluationResults()
      const modes = Object.keys(payload.evaluations ?? {})
      setResults(payload)
      setSelectedMode((current) => current && modes.includes(current) ? current : modes[0] ?? '')
    } catch (error) {
      setResults(null)
      setLoadError({
        message: error instanceof Error ? error.message : 'Evaluation results could not be loaded.',
        missing: error instanceof ApiError && error.status === 404,
      })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void loadResults() }, [])

  const selectedEvaluation = results?.evaluations?.[selectedMode]
  const unavailableBaselines = Object.entries(results?.baselines ?? {})
    .filter(([, baseline]) => baseline.status === 'unavailable')

  return (
    <section className="evaluation-section" id="evaluation" aria-labelledby="evaluation-title">
      <div className="section-heading evaluation-heading">
        <div>
          <h2 id="evaluation-title">Evaluation</h2>
          <p>Stored results from controlled, synthetic local cases</p>
        </div>
        <button className="button-secondary" onClick={() => void loadResults()} disabled={loading}>
          {loading ? 'Loading…' : '↻ Refresh results'}
        </button>
      </div>

      {loading && (
        <div className="panel evaluation-state" role="status">
          <span className="spinner" /> Loading stored evaluation results…
        </div>
      )}

      {!loading && loadError && (
        <div className="panel evaluation-state evaluation-error" role="alert">
          <strong>{loadError.missing ? 'Evaluation results are not available' : 'Could not load evaluation results'}</strong>
          <p>{loadError.missing
            ? 'No generated evaluation.json was found. Run the local evaluation runner, then retry.'
            : loadError.message}</p>
          <button className="button-secondary" onClick={() => void loadResults()}>Retry</button>
        </div>
      )}

      {!loading && !loadError && results && !Object.keys(results.evaluations ?? {}).length && (
        <div className="panel evaluation-state">
          No evaluation modes are present in the stored results.
        </div>
      )}

      {!loading && !loadError && results && selectedEvaluation && (
        <>
          <div className="evaluation-summary">
            <article className="metric-card">
              <div className="metric-top"><span>Synthetic dataset</span><span className="metric-icon cyan">▦</span></div>
              <div className="metric-value">{results.dataset.case_count} cases</div>
              <div className="metric-foot">{results.dataset.id} · v{results.dataset.version}</div>
            </article>
            <article className="metric-card evaluation-mode-card">
              <div className="metric-top"><span>Displayed evaluation mode</span><span className="metric-icon blue">⌘</span></div>
              <label className="evaluation-select-label" htmlFor="evaluation-mode">Stored result</label>
              <select id="evaluation-mode" value={selectedMode} onChange={(event) => setSelectedMode(event.target.value)}>
                {Object.keys(results.evaluations).map((mode) => (
                  <option value={mode} key={mode}>{modeLabels[mode] ?? mode.replaceAll('_', ' ')}</option>
                ))}
              </select>
              <div className="metric-foot">{selectedEvaluation.description}</div>
            </article>
          </div>

          <div className="evaluation-metrics">
            {metricCards.map(([key, label]) => {
              const rawMetric = selectedEvaluation.metrics[key]
              const metric = isMetric(rawMetric) ? rawMetric : undefined
              return (
                <article className="metric-card evaluation-metric" key={key}>
                  <div className="metric-top"><span>{label}</span><span className="evaluation-indicator" /></div>
                  <div className={`metric-value ${metric?.value === null || !metric ? 'unavailable-value' : ''}`}>
                    {metricDisplay(metric)}
                  </div>
                  <div className="metric-foot">
                    {metric
                      ? `${metric.numerator} of ${metric.denominator}${metric.unavailable_reason ? ` · ${metric.unavailable_reason}` : ''}`
                      : 'Metric not present in this evaluation mode'}
                  </div>
                </article>
              )
            })}
          </div>

          <div className="panel evaluation-notice">
            <span className="evaluation-notice-icon">i</span>
            <div>
              <strong>Synthetic evaluation, not a real-world performance claim</strong>
              <p>Results describe this local synthetic dataset only. Unavailable metrics and baselines are shown as unavailable; no scores or rankings are inferred.</p>
            </div>
          </div>

          <article className="panel baseline-panel">
            <div className="panel-heading">
              <div><h2>Baseline availability</h2><p>Unimplemented comparisons have no generated scores</p></div>
              <span className="step-count">{unavailableBaselines.length} UNAVAILABLE</span>
            </div>
            {unavailableBaselines.length ? (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>BASELINE</th><th>STATUS</th><th>DETAIL</th></tr></thead>
                  <tbody>{unavailableBaselines.map(([name, baseline]) => (
                    <tr key={name}>
                      <td>{name.replaceAll('_', ' ')}</td>
                      <td><span className="evaluation-unavailable-badge">Unavailable</span></td>
                      <td>{baseline.notes}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            ) : <p className="evaluation-no-baselines">No unavailable baseline entries are recorded.</p>}
          </article>
        </>
      )}
    </section>
  )
}
