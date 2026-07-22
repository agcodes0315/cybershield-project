import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { vulnPriority, orchestrator, audit } from '../services/api';
import useWebSocket from '../hooks/useWebSocket';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts';

const BAND_COLOR = {
  IMMEDIATE: '#f87171',
  URGENT: '#fb923c',
  SCHEDULED: '#fbbf24',
  MONITOR: '#34d399',
};

const EXPLAIN_RULES = {
  severity: {
    critical: 'CVSS-equivalent severity: Critical',
    high: 'CVSS-equivalent severity: High',
    medium: 'Medium severity',
    low: 'Low severity',
  },
  exposure: {
    internet_facing: 'Internet facing',
    internal_network: 'Internal network only',
    isolated: 'Isolated / air-gapped',
  },
  exploit_status: {
    known_exploited: 'Known exploited in the wild',
    public_poc: 'Public proof-of-concept exists',
    theoretical: 'No known exploit yet',
  },
};

export default function Resilience() {
  const { user } = useAuth();
  const { connected, alerts } = useWebSocket();
  const [queue, setQueue] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [auditStatus, setAuditStatus] = useState(null);
  const [expanded, setExpanded] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');

  const loadAll = async () => {
    setLoadError('');
    try {
      const [q, inc] = await Promise.all([
        vulnPriority.demo(),
        orchestrator.list(),
      ]);
      setQueue(Array.isArray(q.data?.queue) ? q.data.queue : []);
      setIncidents(Array.isArray(inc.data) ? inc.data : []);
    } catch (e) {
      console.error('Resilience load failed', e);
      setLoadError(
        e?.response?.status === 404
          ? 'Backend routes not found (404) — /vuln-priority and /orchestrator may not be registered in the API gateway yet.'
          : 'Could not reach the resilience backend.'
      );
    }
    setLoading(false);
  };

  const checkAuditIntegrity = async () => {
    try {
      const r = await audit.verify();
      setAuditStatus(r.data);
    } catch {
      setAuditStatus({ valid: false, error: true });
    }
  };

  useEffect(() => {
    loadAll();
    checkAuditIntegrity();
    const interval = setInterval(loadAll, 8000);
    return () => clearInterval(interval);
  }, []);

  const criticalAssets = queue.filter(q => q.priority_band === 'IMMEDIATE').length;
  const openIncidents = incidents.filter(
    i => Array.isArray(i.actions) && i.actions.some(a => a.status === 'PENDING_APPROVAL')
  ).length;
  const containedIncidents = incidents.filter(
    i => Array.isArray(i.actions) &&
      i.actions.every(a => a.status !== 'PENDING_APPROVAL' && a.status !== 'AUTO_EXECUTABLE')
  ).length;
  const containmentRate = incidents.length
    ? Math.round((containedIncidents / incidents.length) * 100)
    : 0;
  const overallRisk = criticalAssets > 2 ? 'High' : criticalAssets > 0 ? 'Medium' : 'Low';
  const riskColor = overallRisk === 'High' ? '#f87171' : overallRisk === 'Medium' ? '#fbbf24' : '#34d399';

  const execMetrics = [
    { label: 'Overall Risk', value: overallRisk, color: riskColor, sub: `${criticalAssets} critical findings` },
    { label: 'Open Incidents', value: openIncidents, color: '#38bdf8', sub: 'Awaiting analyst approval' },
    { label: 'Containment Rate', value: `${containmentRate}%`, color: '#818cf8', sub: `${containedIncidents}/${incidents.length || 0} resolved` },
    {
      label: 'Audit Integrity',
      value: auditStatus?.valid ? 'Verified' : auditStatus ? 'BROKEN' : '—',
      color: auditStatus?.valid ? '#34d399' : '#f87171',
      sub: auditStatus?.entries_checked != null ? `${auditStatus.entries_checked} entries checked` : 'Checking...',
    },
  ];

  const chartData = queue.slice(0, 10).map(q => ({
    name: q.asset_name?.length > 14 ? q.asset_name.slice(0, 14) + '…' : q.asset_name,
    score: q.priority_score,
    fill: BAND_COLOR[q.priority_band] || '#556780',
  }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <div className="fade-up">
        <h2 style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--text-1)', letterSpacing: '-0.02em' }}>
          Cyber Resilience Command Center
        </h2>
        <p style={{ fontSize: '0.9rem', color: 'var(--text-3)', marginTop: '4px' }}>
          Detection → Prioritization → Response → Audit, in one operational view.
        </p>
      </div>

      {loadError && (
        <div style={{
          padding: '12px 16px', borderRadius: '12px',
          background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.18)',
          color: '#f87171', fontSize: '0.84rem',
        }}>
          {loadError}
        </div>
      )}

      <div style={{
        display: 'flex', alignItems: 'center', gap: '10px',
        padding: '12px 16px', borderRadius: '14px',
        background: connected ? 'rgba(34,197,94,0.08)' : 'rgba(248,113,113,0.08)',
        border: connected ? '1px solid rgba(34,197,94,0.18)' : '1px solid rgba(248,113,113,0.18)',
      }}>
        <div style={{ width: 10, height: 10, borderRadius: '999px', background: connected ? '#22c55e' : '#f87171' }} />
        <span style={{ fontSize: '0.84rem', fontWeight: 700, color: connected ? '#4ade80' : '#f87171' }}>
          {connected ? 'Live Detection Feed Connected' : 'Feed Disconnected'}
        </span>
        {alerts.length > 0 && (
          <span style={{ marginLeft: 'auto', padding: '4px 10px', borderRadius: '999px', background: 'rgba(248,113,113,0.12)', color: '#f87171', fontSize: '0.76rem', fontWeight: 700 }}>
            {alerts.length} new alert{alerts.length > 1 ? 's' : ''}
          </span>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        {execMetrics.map((s, i) => (
          <div key={i} style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: '16px', padding: '22px 24px', borderLeft: `3px solid ${s.color}`,
            minHeight: '110px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between',
          }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-3)' }}>{s.label}</span>
            <div>
              <div style={{ fontSize: '1.7rem', fontWeight: 800, color: s.color, lineHeight: 1 }}>{s.value}</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-3)', marginTop: '6px' }}>{s.sub}</div>
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '16px', padding: '24px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-1)', marginBottom: '14px' }}>
            Remediation Priority Queue
          </h3>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={chartData} barSize={28}>
              <XAxis dataKey="name" tick={{ fill: '#556780', fontSize: 10 }} tickLine={false} />
              <YAxis domain={[0, 100]} tick={{ fill: '#556780', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: '#111a2d', border: '1px solid rgba(56,189,248,0.15)', borderRadius: '10px', fontSize: '0.8rem' }} />
              <Bar dataKey="score" radius={[8, 8, 0, 0]}>
                {chartData.map((e, i) => <Cell key={i} fill={e.fill} fillOpacity={0.9} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '16px', padding: '24px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-1)', marginBottom: '14px' }}>
            Active Incidents
          </h3>
          {incidents.length === 0 && <p style={{ color: 'var(--text-3)', fontSize: '0.85rem' }}>No active incidents — clean.</p>}
          {incidents.slice(0, 5).map(inc => {
            const actions = Array.isArray(inc.actions) ? inc.actions : [];
            const pending = actions.filter(a => a.status === 'PENDING_APPROVAL').length;
            return (
              <div key={inc.incident_id} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderTop: '1px solid var(--border)', fontSize: '0.84rem' }}>
                <div>
                  <div style={{ fontWeight: 700, color: 'var(--text-1)' }}>{inc.incident_id}</div>
                  <div style={{ color: 'var(--text-3)', fontSize: '0.76rem' }}>{inc.detection?.target}</div>
                </div>
                <span style={{
                  alignSelf: 'center', padding: '4px 12px', borderRadius: '20px', fontSize: '0.72rem', fontWeight: 700,
                  background: pending > 0 ? 'rgba(251,146,60,0.12)' : 'rgba(52,211,153,0.12)',
                  color: pending > 0 ? '#fb923c' : '#34d399',
                }}>
                  {pending > 0 ? `${pending} awaiting approval` : 'Resolved'}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '16px', padding: '28px' }}>
        <div style={{ marginBottom: '18px' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-1)' }}>Vulnerability Prioritisation — Explainable</h3>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-3)', marginTop: '4px' }}>
            Every score is reasoned, not a black box. Click a row to see why.
          </p>
        </div>

        {loading && <p style={{ color: 'var(--text-3)' }}>Loading queue...</p>}
        {!loading && queue.length === 0 && !loadError && (
          <p style={{ color: 'var(--text-3)', fontSize: '0.85rem' }}>No findings returned yet.</p>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {queue.map((q, i) => (
            <div key={i}>
              <div
                onClick={() => setExpanded(expanded === i ? null : i)}
                style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '16px 20px', borderRadius: '12px', cursor: 'pointer',
                  background: 'var(--bg-surface)', border: '1px solid var(--border)',
                }}
              >
                <div>
                  <div style={{ fontWeight: 700, color: 'var(--text-1)', fontSize: '0.9rem' }}>{q.asset_name}</div>
                  <div style={{ color: 'var(--text-3)', fontSize: '0.78rem', marginTop: '2px' }}>{q.finding}</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>{q.recommended_action_window}</span>
                  <span style={{
                    padding: '6px 14px', borderRadius: '20px', fontSize: '0.78rem', fontWeight: 700,
                    background: `${BAND_COLOR[q.priority_band]}18`, color: BAND_COLOR[q.priority_band],
                  }}>
                    {q.priority_band} · {q.priority_score}
                  </span>
                </div>
              </div>

              {expanded === i && (
                <div style={{ padding: '16px 20px', marginTop: '2px', borderRadius: '12px', background: 'var(--bg-input)', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-3)', textTransform: 'uppercase', marginBottom: '10px' }}>
                    Why priority = {q.priority_score}?
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '0.84rem', color: 'var(--text-2)' }}>
                    <div>✓ {EXPLAIN_RULES.severity[q.severity?.toLowerCase()] || q.severity}</div>
                    <div>✓ {EXPLAIN_RULES.exposure[q.exposure?.toLowerCase()] || q.exposure}</div>
                    <div>✓ {EXPLAIN_RULES.exploit_status[q.exploit_status?.toLowerCase()] || q.exploit_status}</div>
                    <div>✓ Asset criticality: {q.asset_criticality}/5</div>
                    {q.cve_id && <div>✓ Reference: {q.cve_id}</div>}
                  </div>
                  <div style={{ marginTop: '12px', fontSize: '0.84rem', fontWeight: 700, color: BAND_COLOR[q.priority_band] }}>
                    Recommended: {q.recommended_action_window}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}