import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Play,
  RefreshCw,
  ShieldCheck,
  XCircle,
  Zap,
} from 'lucide-react';

import { useAuth } from '../context/AuthContext';
import { audit, orchestrator } from '../services/api';
import './ResponseOrchestrator.css';

const AUTO_READY_STATUSES = new Set([
  'AUTO_EXECUTABLE',
  'READY_FOR_AUTO_EXECUTION',
]);

const COMPLETE_STATUSES = new Set([
  'APPROVED',
  'EXECUTED',
  'SIMULATED_SUCCESS',
  'COMPLETED',
]);

const getIncidentId = (incident, index = 0) =>
  incident?.incident_id || incident?.id || `incident-${index}`;

const getActions = (incident) =>
  Array.isArray(incident?.actions) ? incident.actions : [];

const normaliseIncidents = (data) => {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.incidents)) return data.incidents;
  if (Array.isArray(data?.items)) return data.items;
  return [];
};

const normaliseTrail = (data) => {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.trail)) return data.trail;
  if (Array.isArray(data?.entries)) return data.entries;
  return [];
};

const statusTone = (status) => {
  const value = String(status || '').toUpperCase();
  if (COMPLETE_STATUSES.has(value)) return 'success';
  if (value === 'REJECTED' || value === 'FAILED') return 'danger';
  if (value === 'PENDING_APPROVAL' || value === 'AWAITING_HUMAN_APPROVAL') return 'warning';
  if (AUTO_READY_STATUSES.has(value)) return 'info';
  return 'neutral';
};

const formatLabel = (value, fallback = 'Unknown') => {
  if (!value) return fallback;
  return String(value)
    .replace(/_/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
};

const formatConfidence = (value) => {
  const number = Number(value);
  if (!Number.isFinite(number)) return 'N/A';
  return `${Math.round(number <= 1 ? number * 100 : number)}%`;
};

const formatDateTime = (value) => {
  if (!value) return 'Time unavailable';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
};

const formatTime = (value) => {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleTimeString();
};

const blastTone = (value) => {
  const level = String(value || '').toUpperCase();
  if (level === 'LOW') return 'success';
  if (level === 'MEDIUM') return 'warning';
  if (level === 'HIGH') return 'orange';
  if (level === 'CRITICAL') return 'danger';
  return 'neutral';
};

export default function ResponseOrchestrator() {
  const { user } = useAuth();
  const [incidents, setIncidents] = useState([]);
  const [selected, setSelected] = useState(null);
  const [trail, setTrail] = useState([]);
  const [loading, setLoading] = useState(true);
  const [trailLoading, setTrailLoading] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [actionError, setActionError] = useState('');
  const [busyAction, setBusyAction] = useState('');
  const [lastUpdated, setLastUpdated] = useState(null);

  const loadIncidents = useCallback(async ({ showLoading = false } = {}) => {
    if (showLoading) setLoading(true);

    try {
      const response = await orchestrator.list();
      const list = normaliseIncidents(response?.data);

      setIncidents(list);
      setLoadError('');
      setLastUpdated(new Date());
      setSelected((current) => {
        if (!list.length) return null;
        const exists = list.some(
          (incident, index) => getIncidentId(incident, index) === current,
        );
        return exists ? current : getIncidentId(list[0], 0);
      });
    } catch (error) {
      console.error('Failed to load incidents:', error);
      if (error?.response?.status === 404) {
        setLoadError(
          'The orchestrator route was not found. Confirm that the resilience orchestrator routes are registered in the API gateway.',
        );
      } else if (error?.code === 'ECONNABORTED') {
        setLoadError('The orchestrator request timed out.');
      } else {
        setLoadError(
          'Could not load incidents. Confirm that the API gateway and detection engine are running.',
        );
      }
    } finally {
      setLoading(false);
    }
  }, []);

  const loadTrail = useCallback(async (incidentId) => {
    if (!incidentId) {
      setTrail([]);
      return;
    }

    setTrailLoading(true);
    try {
      const response = await audit.trail(incidentId);
      setTrail(normaliseTrail(response?.data));
    } catch (error) {
      console.error('Failed to load audit trail:', error);
      setTrail([]);
    } finally {
      setTrailLoading(false);
    }
  }, []);

  useEffect(() => {
    loadIncidents({ showLoading: true });
    const intervalId = window.setInterval(() => loadIncidents(), 6000);
    return () => window.clearInterval(intervalId);
  }, [loadIncidents]);

  useEffect(() => {
    loadTrail(selected);
  }, [selected, loadTrail]);

  const activeIncident = useMemo(
    () =>
      incidents.find(
        (incident, index) => getIncidentId(incident, index) === selected,
      ) || null,
    [incidents, selected],
  );

  const activeActions = getActions(activeIncident);

  const metrics = useMemo(() => {
    const actions = incidents.flatMap((incident) => getActions(incident));
    return {
      incidents: incidents.length,
      pending: actions.filter(
        (action) => String(action?.status || '').toUpperCase() === 'PENDING_APPROVAL',
      ).length,
      ready: actions.filter((action) =>
        AUTO_READY_STATUSES.has(String(action?.status || '').toUpperCase()),
      ).length,
      resolved: actions.filter((action) =>
        COMPLETE_STATUSES.has(String(action?.status || '').toUpperCase()),
      ).length,
    };
  }, [incidents]);

  const decide = async (incidentId, actionIndex, decision) => {
    const key = `${incidentId}-${actionIndex}-${decision}`;
    setBusyAction(key);
    setActionError('');

    try {
      await orchestrator.decide(incidentId, {
        approver: user?.username || user?.name || user?.email || 'analyst',
        decision,
        action_index: actionIndex,
      });
      await Promise.all([loadIncidents(), loadTrail(incidentId)]);
    } catch (error) {
      console.error('Decision failed:', error);
      setActionError(
        error?.response?.data?.detail ||
          error?.response?.data?.message ||
          'The decision could not be recorded. Check the backend logs.',
      );
    } finally {
      setBusyAction('');
    }
  };

  const autoExecute = async (incidentId) => {
    const key = `${incidentId}-execute`;
    setBusyAction(key);
    setActionError('');

    try {
      await orchestrator.autoExecute(incidentId);
      await Promise.all([loadIncidents(), loadTrail(incidentId)]);
    } catch (error) {
      console.error('Auto-execution failed:', error);
      setActionError(
        error?.response?.data?.detail ||
          error?.response?.data?.message ||
          'The approved response could not be executed.',
      );
    } finally {
      setBusyAction('');
    }
  };

  const canExecute = activeActions.some((action) =>
    AUTO_READY_STATUSES.has(String(action?.status || '').toUpperCase()),
  );

  return (
    <main className="ro-page">
      <section className="ro-hero">
        <div>
          <span className="ro-eyebrow">Cyber Resilience · SOAR Simulation</span>
          <h1>Response Orchestrator</h1>
          <p>
            Review prioritized incidents, approve high-impact actions, execute
            low-risk playbooks, and verify every decision in the audit ledger.
          </p>
        </div>

        <div className="ro-live-card">
          <span className="ro-live-dot" />
          <div>
            <strong>Simulation mode active</strong>
            <small>
              {lastUpdated
                ? `Updated ${lastUpdated.toLocaleTimeString()}`
                : 'Connecting to orchestrator'}
            </small>
          </div>
          <button
            type="button"
            className="ro-icon-button"
            onClick={() => loadIncidents({ showLoading: true })}
            aria-label="Refresh incidents"
          >
            <RefreshCw size={16} />
          </button>
        </div>
      </section>

      {loadError && <div className="ro-alert ro-alert-danger">{loadError}</div>}
      {actionError && <div className="ro-alert ro-alert-warning">{actionError}</div>}

      <section className="ro-metrics">
        <article><ShieldCheck /><span>Total incidents</span><strong>{metrics.incidents}</strong><small>Active response cases</small></article>
        <article><Clock3 /><span>Awaiting approval</span><strong>{metrics.pending}</strong><small>Human decision required</small></article>
        <article><Zap /><span>Auto executable</span><strong>{metrics.ready}</strong><small>Low-risk simulated actions</small></article>
        <article><CheckCircle2 /><span>Resolved actions</span><strong>{metrics.resolved}</strong><small>Approved or executed</small></article>
      </section>

      <section className="ro-workspace">
        <aside className="ro-panel ro-queue">
          <div className="ro-panel-title">
            <div><span>Incident Queue</span><h2>Response cases</h2></div>
            <b>{incidents.length}</b>
          </div>

          {loading && <div className="ro-state">Loading incidents…</div>}
          {!loading && incidents.length === 0 && (
            <div className="ro-empty"><Activity size={28} /><strong>No incidents available</strong><span>Create or trigger an incident through the orchestrator API.</span></div>
          )}

          <div className="ro-incident-list">
            {incidents.map((incident, index) => {
              const incidentId = getIncidentId(incident, index);
              const actions = getActions(incident);
              const pending = actions.filter(
                (action) => String(action?.status || '').toUpperCase() === 'PENDING_APPROVAL',
              ).length;

              return (
                <button
                  type="button"
                  key={incidentId}
                  className={`ro-incident ${selected === incidentId ? 'is-selected' : ''}`}
                  onClick={() => setSelected(incidentId)}
                >
                  <div className="ro-incident-top">
                    <strong>{incidentId}</strong>
                    <span className={`ro-badge tone-${statusTone(incident?.status)}`}>
                      {formatLabel(incident?.status, 'Open')}
                    </span>
                  </div>
                  <p>{incident?.detection?.target || incident?.target || 'Unknown target'}</p>
                  <div className="ro-incident-meta">
                    <span>{actions.length} actions</span>
                    <span>{pending} pending</span>
                    <span>{formatConfidence(incident?.detection?.confidence ?? incident?.confidence)}</span>
                  </div>
                </button>
              );
            })}
          </div>
        </aside>

        <div className="ro-main-column">
          {activeIncident ? (
            <>
              <section className="ro-panel ro-details">
                <div className="ro-detail-header">
                  <div>
                    <span className="ro-kicker">Selected incident</span>
                    <h2>{getIncidentId(activeIncident)}</h2>
                    <p>{activeIncident?.detection?.target || activeIncident?.target || 'Unknown target'}</p>
                  </div>
                  <div className="ro-detail-status">
                    <span className={`ro-badge tone-${statusTone(activeIncident?.status)}`}>
                      {formatLabel(activeIncident?.status, 'Open')}
                    </span>
                    <small>{formatDateTime(activeIncident?.updated_at || activeIncident?.created_at || activeIncident?.timestamp)}</small>
                  </div>
                </div>

                <div className="ro-intel-grid">
                  <div><span>Detection source</span><strong>{activeIncident?.detection?.source || activeIncident?.source || 'Unknown'}</strong></div>
                  <div><span>Confidence</span><strong>{formatConfidence(activeIncident?.detection?.confidence ?? activeIncident?.confidence)}</strong></div>
                  <div><span>Execution mode</span><strong>{formatLabel(activeIncident?.execution_mode, 'Simulation')}</strong></div>
                  <div><span>Assigned analyst</span><strong>{user?.name || user?.username || user?.email || 'SOC analyst'}</strong></div>
                </div>

                <div className="ro-rationale">
                  <span>Detection rationale</span>
                  <p>{activeIncident?.detection?.reason || activeIncident?.reason || 'No detection explanation was provided.'}</p>
                </div>

                <div className="ro-section-heading">
                  <div><span>Generated playbook</span><h3>Recommended response actions</h3></div>
                  <b>{activeActions.length} steps</b>
                </div>

                <div className="ro-action-list">
                  {activeActions.length === 0 && <div className="ro-state">No recommended actions were returned.</div>}
                  {activeActions.map((action, index) => {
                    const incidentId = getIncidentId(activeIncident);
                    const status = String(action?.status || 'UNKNOWN').toUpperCase();
                    const approveKey = `${incidentId}-${index}-approve`;
                    const rejectKey = `${incidentId}-${index}-reject`;
                    const isPending = status === 'PENDING_APPROVAL';

                    return (
                      <article className="ro-action" key={action?.action_id || `${incidentId}-${index}`}>
                        <div className="ro-action-number">{index + 1}</div>
                        <div className="ro-action-copy">
                          <strong>{action?.action || action?.name || 'Unnamed response action'}</strong>
                          <span className={`ro-risk tone-${blastTone(action?.blast_radius)}`}>
                            {formatLabel(action?.blast_radius, 'Unknown')} blast radius
                          </span>
                        </div>
                        <div className="ro-action-side">
                          <span className={`ro-badge tone-${statusTone(status)}`}>{formatLabel(status)}</span>
                          {isPending && (
                            <div className="ro-decision-buttons">
                              <button type="button" className="approve" disabled={Boolean(busyAction)} onClick={() => decide(incidentId, index, 'approve')}>
                                <CheckCircle2 size={14} />{busyAction === approveKey ? 'Approving…' : 'Approve'}
                              </button>
                              <button type="button" className="reject" disabled={Boolean(busyAction)} onClick={() => decide(incidentId, index, 'reject')}>
                                <XCircle size={14} />{busyAction === rejectKey ? 'Rejecting…' : 'Reject'}
                              </button>
                            </div>
                          )}
                        </div>
                      </article>
                    );
                  })}
                </div>

                {canExecute && (
                  <div className="ro-execute-banner">
                    <div><Zap size={20} /><span><strong>Approved actions are ready</strong><small>Execution remains simulated and will not modify live infrastructure.</small></span></div>
                    <button type="button" disabled={Boolean(busyAction)} onClick={() => autoExecute(getIncidentId(activeIncident))}>
                      <Play size={15} />{busyAction === `${getIncidentId(activeIncident)}-execute` ? 'Executing…' : 'Execute approved response'}
                    </button>
                  </div>
                )}
              </section>

              <section className="ro-panel ro-audit">
                <div className="ro-panel-title">
                  <div><span>Governance</span><h2>Audit timeline</h2></div>
                  <b>{trail.length}</b>
                </div>

                {trailLoading && <div className="ro-state">Loading audit entries…</div>}
                {!trailLoading && trail.length === 0 && <div className="ro-state">No audit entries recorded for this incident.</div>}
                {!trailLoading && trail.length > 0 && (
                  <div className="ro-timeline">
                    {trail.map((entry, index) => (
                      <div className="ro-timeline-entry" key={entry?.id || entry?.entry_id || `${entry?.created_at}-${index}`}>
                        <div className="ro-timeline-rail"><span />{index < trail.length - 1 && <i />}</div>
                        <div>
                          <div className="ro-timeline-top"><strong>{formatLabel(entry?.action || entry?.event, 'Audit event')}</strong><time>{formatTime(entry?.created_at || entry?.timestamp)}</time></div>
                          <p>Performed by <b>{entry?.actor || entry?.user || 'system'}</b>{(entry?.target || entry?.resource) ? ` on ${entry?.target || entry?.resource}` : ''}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            </>
          ) : (
            <section className="ro-panel ro-no-selection"><AlertTriangle size={30} />{loading ? 'Loading incident information…' : 'Select an incident to inspect its response workflow.'}</section>
          )}
        </div>
      </section>
    </main>
  );
}