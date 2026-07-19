import { useMemo, useState } from 'react';
import { yaraScan } from '../services/api';

const STAGES = [
  'Validating target',
  'Fetching page safely',
  'Compiling YARA rules',
  'Scanning content',
  'Calculating confidence',
  'Finalising report',
];

const toneMap = {
  success: { background: 'rgba(34,197,94,0.12)', color: '#4ade80', border: '1px solid rgba(34,197,94,0.18)' },
  danger: { background: 'rgba(248,113,113,0.12)', color: '#f87171', border: '1px solid rgba(248,113,113,0.18)' },
  warning: { background: 'rgba(251,146,60,0.12)', color: '#fb923c', border: '1px solid rgba(251,146,60,0.18)' },
  info: { background: 'rgba(56,189,248,0.12)', color: '#38bdf8', border: '1px solid rgba(56,189,248,0.18)' },
  critical: { background: 'rgba(168,85,247,0.12)', color: '#c084fc', border: '1px solid rgba(168,85,247,0.18)' },
  neutral: { background: 'rgba(148,163,184,0.10)', color: 'var(--text-2)', border: '1px solid rgba(148,163,184,0.12)' },
};

function Badge({ label, tone = 'neutral' }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', padding: '5px 12px', borderRadius: 999, fontSize: '0.72rem', fontWeight: 750, whiteSpace: 'nowrap', ...(toneMap[tone] || toneMap.neutral) }}>
      {label}
    </span>
  );
}

function severityTone(value) {
  const severity = String(value || '').toLowerCase();
  if (severity === 'critical') return 'critical';
  if (severity === 'high') return 'danger';
  if (severity === 'medium') return 'warning';
  if (severity === 'low') return 'info';
  return 'neutral';
}

function riskTone(score) {
  const value = Number(score || 0);
  if (value >= 70) return 'critical';
  if (value >= 45) return 'danger';
  if (value >= 20) return 'warning';
  if (value > 0) return 'info';
  return 'success';
}

function getError(error) {
  return error?.response?.data?.detail || error?.response?.data?.error || error?.response?.data?.message || error?.message || 'The request could not be completed.';
}

function ProgressPanel({ stageIndex }) {
  const progress = Math.round(((stageIndex + 1) / STAGES.length) * 100);
  return (
    <section style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 18, padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, marginBottom: 12 }}>
        <div>
          <div style={{ color: 'var(--text-1)', fontWeight: 850 }}>Running YARA assessment</div>
          <div style={{ color: 'var(--text-3)', fontSize: '0.8rem', marginTop: 4 }}>{STAGES[stageIndex]}</div>
        </div>
        <strong style={{ color: '#c084fc' }}>{progress}%</strong>
      </div>
      <div style={{ height: 9, borderRadius: 999, background: 'rgba(148,163,184,0.12)', overflow: 'hidden' }}>
        <div style={{ width: `${progress}%`, height: '100%', borderRadius: 999, background: 'linear-gradient(90deg, #a855f7, #6366f1)', transition: 'width 350ms ease' }} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 8, marginTop: 18 }}>
        {STAGES.map((stage, index) => (
          <div key={stage} style={{ padding: 10, borderRadius: 10, background: index <= stageIndex ? 'rgba(168,85,247,0.09)' : 'var(--bg-surface)', border: index <= stageIndex ? '1px solid rgba(168,85,247,0.18)' : '1px solid var(--border)', color: index <= stageIndex ? '#c084fc' : 'var(--text-3)', fontSize: '0.76rem', fontWeight: 700 }}>
            {index < stageIndex ? '✓ ' : index === stageIndex ? '● ' : '○ '}{stage}
          </div>
        ))}
      </div>
    </section>
  );
}

function SeverityChart({ matches }) {
  const counts = useMemo(() => {
    const next = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    matches.forEach((match) => {
      const key = String(match.severity || 'informational').toLowerCase();
      if (Object.hasOwn(next, key)) next[key] += 1;
    });
    return next;
  }, [matches]);

  const rows = [
    ['Critical', counts.critical, '#c084fc'],
    ['High', counts.high, '#f87171'],
    ['Medium', counts.medium, '#fb923c'],
    ['Low', counts.low, '#38bdf8'],
    ['Informational', counts.informational, '#94a3b8'],
  ];
  const max = Math.max(1, ...Object.values(counts));

  return (
    <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 14, padding: 18 }}>
      <div style={{ color: 'var(--text-1)', fontWeight: 800, marginBottom: 14 }}>Severity distribution</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
        {rows.map(([label, value, color]) => (
          <div key={label} style={{ display: 'grid', gridTemplateColumns: '100px 1fr 30px', gap: 10, alignItems: 'center' }}>
            <span style={{ color: 'var(--text-3)', fontSize: '0.76rem' }}>{label}</span>
            <div style={{ height: 9, borderRadius: 999, background: 'rgba(148,163,184,0.12)', overflow: 'hidden' }}>
              <div style={{ width: `${(value / max) * 100}%`, minWidth: value ? 8 : 0, height: '100%', borderRadius: 999, background: color }} />
            </div>
            <strong style={{ color, textAlign: 'right' }}>{value}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function YaraScan() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [rules, setRules] = useState(null);
  const [tab, setTab] = useState('scan');
  const [scanning, setScanning] = useState(false);
  const [stageIndex, setStageIndex] = useState(0);
  const [error, setError] = useState('');
  const [ruleSearch, setRuleSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');

  const card = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 18, padding: 24 };
  const soft = { background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 14, padding: 16 };

  const filteredRules = useMemo(() => {
    const query = ruleSearch.trim().toLowerCase();
    return (rules?.rules || []).filter((rule) => {
      const searchOk = !query || [rule.name, rule.description, rule.category, rule.mitre_attack].some((value) => String(value || '').toLowerCase().includes(query));
      const severityOk = severityFilter === 'all' || rule.severity === severityFilter;
      return searchOk && severityOk;
    });
  }, [rules, ruleSearch, severityFilter]);

  const doScan = async () => {
    if (!url.trim() || scanning) return;
    setScanning(true);
    setResult(null);
    setError('');
    setStageIndex(0);
    const timer = window.setInterval(() => setStageIndex((value) => Math.min(value + 1, STAGES.length - 1)), 700);
    try {
      const response = await yaraScan.scan(url.trim());
      if (response.data?.error) throw new Error(response.data.error);
      setResult(response.data);
    } catch (requestError) {
      setError(getError(requestError));
    } finally {
      window.clearInterval(timer);
      setScanning(false);
    }
  };

  const loadRules = async () => {
    setError('');
    try {
      const response = await yaraScan.getRules();
      setRules(response.data);
    } catch (requestError) {
      setError(getError(requestError));
    }
  };

  const switchTab = (nextTab) => {
    setTab(nextTab);
    setError('');
    if (nextTab === 'rules' && !rules) loadRules();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <header>
        <div style={{ color: '#38bdf8', fontSize: '0.72rem', fontWeight: 900, letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 8 }}>Web content intelligence</div>
        <h2 style={{ margin: 0, fontSize: '1.7rem', fontWeight: 900, color: 'var(--text-1)' }}>YARA Web Intelligence Scanner</h2>
        <p style={{ fontSize: '0.9rem', color: 'var(--text-3)', margin: '7px 0 0', lineHeight: 1.55 }}>Evaluate authorised web content against phishing, credential-harvesting and obfuscation rules with confidence-aware scoring.</p>
      </header>

      <div style={{ padding: 15, borderRadius: 13, background: 'rgba(251,146,60,0.08)', border: '1px solid rgba(251,146,60,0.20)', color: 'var(--text-2)', fontSize: '0.8rem', lineHeight: 1.5 }}>
        <strong style={{ color: '#fb923c' }}>Authorised testing only. </strong>Private and local network targets are blocked. A YARA match is an indicator and still requires analyst review.
      </div>

      <nav style={{ display: 'flex', gap: 8 }}>
        {[['scan', 'Scan'], ['rules', 'Rules']].map(([value, label]) => (
          <button key={value} type="button" onClick={() => switchTab(value)} style={{ padding: '10px 22px', borderRadius: 10, cursor: 'pointer', fontSize: '0.85rem', fontWeight: 700, fontFamily: 'inherit', background: tab === value ? 'rgba(168,85,247,0.12)' : 'transparent', color: tab === value ? '#c084fc' : 'var(--text-3)', border: tab === value ? '1px solid rgba(168,85,247,0.18)' : '1px solid transparent' }}>{label}</button>
        ))}
      </nav>

      {error && <div role="alert" style={{ padding: '14px 18px', borderRadius: 12, background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.18)', color: '#f87171', fontWeight: 650 }}>{error}</div>}

      {tab === 'scan' && (
        <>
          <section style={card}>
            <label htmlFor="yara-target" style={{ display: 'block', color: 'var(--text-2)', fontSize: '0.78rem', fontWeight: 800, marginBottom: 9 }}>Public URL</label>
            <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
              <input id="yara-target" value={url} onChange={(event) => setUrl(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && doScan()} placeholder="https://example.com" disabled={scanning} style={{ flex: '1 1 420px', minWidth: 0, padding: '14px 16px', borderRadius: 12, background: 'var(--bg-input)', border: '1px solid var(--border)', color: 'var(--text-1)', fontSize: '0.9rem', outline: 'none', fontFamily: 'inherit' }} />
              <button type="button" onClick={doScan} disabled={scanning} style={{ padding: '14px 28px', borderRadius: 12, border: 'none', background: 'linear-gradient(135deg, #a855f7, #6366f1)', color: 'white', fontWeight: 800, cursor: scanning ? 'not-allowed' : 'pointer', opacity: scanning ? 0.6 : 1 }}>{scanning ? 'Scanning...' : 'Run YARA Assessment'}</button>
            </div>
            <p style={{ margin: '10px 0 0', color: 'var(--text-3)', fontSize: '0.75rem' }}>Safe test target: https://example.com</p>
          </section>

          {scanning && <ProgressPanel stageIndex={stageIndex} />}

          {result && !scanning && (
            <>
              <section style={card}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, alignItems: 'flex-start', marginBottom: 18 }}>
                  <div>
                    <h3 style={{ margin: '0 0 5px', color: 'var(--text-1)' }}>Scan results</h3>
                    <p style={{ margin: 0, color: 'var(--text-3)', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.78rem', overflowWrap: 'anywhere' }}>{result.final_url || result.url}</p>
                  </div>
                  <Badge label={`${result.risk_level} — Score ${result.risk_score}`} tone={riskTone(result.risk_score)} />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, marginBottom: 18 }}>
                  {[
                    ['Rules matched', result.total_matches, result.total_matches ? '#f87171' : '#4ade80'],
                    ['Rules compiled', `${result.rules_loaded}/${result.rules_defined}`, '#38bdf8'],
                    ['Status code', result.status_code || 'N/A', 'var(--text-1)'],
                    ['Risk score', `${result.risk_score}%`, Number(result.risk_score) >= 45 ? '#f87171' : Number(result.risk_score) >= 20 ? '#fb923c' : '#4ade80'],
                  ].map(([label, value, color]) => (
                    <article key={label} style={soft}>
                      <div style={{ color: 'var(--text-3)', fontSize: '0.69rem', fontWeight: 800, textTransform: 'uppercase', marginBottom: 8 }}>{label}</div>
                      <div style={{ color, fontSize: '1.35rem', fontWeight: 900 }}>{value}</div>
                    </article>
                  ))}
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 14 }}>
                  <div style={soft}>
                    <div style={{ color: 'var(--text-1)', fontWeight: 800, marginBottom: 8 }}>Executive summary</div>
                    <p style={{ color: 'var(--text-2)', fontSize: '0.83rem', lineHeight: 1.6, margin: 0 }}>{result.executive_summary?.headline}</p>
                    <div style={{ marginTop: 12, color: 'var(--text-3)', fontSize: '0.76rem' }}>High-confidence matches: <strong style={{ color: '#c084fc' }}>{result.executive_summary?.high_confidence_matches || 0}</strong></div>
                  </div>
                  <SeverityChart matches={result.matches || []} />
                </div>
              </section>

              <section style={card}>
                <div style={{ color: 'var(--text-3)', fontSize: '0.74rem', fontWeight: 800, textTransform: 'uppercase', marginBottom: 11 }}>Page characteristics</div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <Badge label={result.page_analysis?.has_forms ? 'Forms detected' : 'No forms'} tone={result.page_analysis?.has_forms ? 'warning' : 'success'} />
                  <Badge label={result.page_analysis?.has_password_field ? 'Password field found' : 'No password fields'} tone={result.page_analysis?.has_password_field ? 'danger' : 'success'} />
                  <Badge label={result.page_analysis?.has_iframe ? 'iFrame detected' : 'No iFrames'} tone={result.page_analysis?.has_iframe ? 'warning' : 'neutral'} />
                  <Badge label={result.page_analysis?.has_obfuscation ? 'Obfuscation detected' : 'No obfuscation'} tone={result.page_analysis?.has_obfuscation ? 'danger' : 'success'} />
                  <Badge label={`${result.page_analysis?.external_links_count || 0} external links`} tone="info" />
                </div>
              </section>

              <section style={card}>
                <div style={{ color: 'var(--text-3)', fontSize: '0.74rem', fontWeight: 800, textTransform: 'uppercase', marginBottom: 12 }}>Matched YARA evidence</div>
                {result.matches?.length ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    {result.matches.map((match) => (
                      <article key={match.rule_name} style={soft}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 14, alignItems: 'flex-start', marginBottom: 9 }}>
                          <div>
                            <div style={{ color: 'var(--text-1)', fontWeight: 850 }}>{match.rule_name}</div>
                            <div style={{ color: 'var(--text-3)', fontSize: '0.74rem', marginTop: 4 }}>MITRE ATT&CK: {match.mitre_attack}</div>
                          </div>
                          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                            <Badge label={match.severity} tone={severityTone(match.severity)} />
                            <Badge label={`${match.confidence}% confidence`} tone={match.confidence >= 70 ? 'danger' : match.confidence >= 55 ? 'warning' : 'neutral'} />
                            <Badge label={`${match.false_positive_likelihood} false-positive likelihood`} tone="neutral" />
                            <Badge label={`+${match.score_contribution} pts`} tone="warning" />
                          </div>
                        </div>
                        <p style={{ color: 'var(--text-2)', fontSize: '0.82rem', lineHeight: 1.55 }}>{match.description}</p>
                        <div style={{ color: '#38bdf8', fontSize: '0.78rem', marginBottom: 10 }}>Analyst action: {match.recommendation}</div>
                        {match.matched_strings?.map((item, index) => (
                          <div key={`${item.identifier}-${index}`} style={{ fontSize: '0.76rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-3)', padding: '6px 8px', borderRadius: 7, background: 'var(--bg-card)', marginTop: 5, overflowWrap: 'anywhere' }}>{item.identifier}: {item.matched_text}</div>
                        ))}
                      </article>
                    ))}
                  </div>
                ) : (
                  <div style={{ padding: 36, textAlign: 'center', borderRadius: 12, border: '1px dashed rgba(34,197,94,0.16)', color: '#4ade80' }}>No configured YARA rules matched.</div>
                )}
              </section>
            </>
          )}
        </>
      )}

      {tab === 'rules' && (
        <>
          <section style={{ ...card, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <input value={ruleSearch} onChange={(event) => setRuleSearch(event.target.value)} placeholder="Search rules, categories or MITRE IDs" style={{ flex: '1 1 320px', padding: '12px 14px', borderRadius: 11, background: 'var(--bg-input)', border: '1px solid var(--border)', color: 'var(--text-1)' }} />
            <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)} style={{ padding: '12px 14px', borderRadius: 11, background: 'var(--bg-input)', border: '1px solid var(--border)', color: 'var(--text-1)' }}>
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <button type="button" onClick={loadRules} style={{ padding: '12px 18px', borderRadius: 11, border: 'none', background: 'linear-gradient(135deg, #a855f7, #6366f1)', color: 'white', fontWeight: 800 }}>Refresh rules</button>
          </section>

          {rules && (
            <section style={{ ...card, padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: 18, borderBottom: '1px solid var(--border)', color: 'var(--text-2)' }}>{rules.compiled}/{rules.total} rules compiled successfully</div>
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', minWidth: 900, borderCollapse: 'collapse', fontSize: '0.83rem' }}>
                  <thead>
                    <tr style={{ background: 'var(--bg-surface)' }}>
                      {['Rule name', 'Description', 'Severity', 'Category', 'MITRE', 'Status'].map((heading) => <th key={heading} style={{ textAlign: 'left', padding: '14px 18px', color: 'var(--text-3)', fontSize: '0.68rem', textTransform: 'uppercase' }}>{heading}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredRules.map((rule) => (
                      <tr key={rule.name} style={{ borderTop: '1px solid var(--border)' }}>
                        <td style={{ padding: '14px 18px', color: 'var(--text-1)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>{rule.name}</td>
                        <td style={{ padding: '14px 18px', color: 'var(--text-2)' }}>{rule.description}</td>
                        <td style={{ padding: '14px 18px' }}><Badge label={rule.severity} tone={severityTone(rule.severity)} /></td>
                        <td style={{ padding: '14px 18px' }}><Badge label={rule.category} tone="info" /></td>
                        <td style={{ padding: '14px 18px', color: 'var(--text-2)' }}>{rule.mitre_attack}</td>
                        <td style={{ padding: '14px 18px' }}><Badge label={rule.compiled ? 'Compiled' : 'Failed'} tone={rule.compiled ? 'success' : 'danger'} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </>
      )}
    </div>
  );
}