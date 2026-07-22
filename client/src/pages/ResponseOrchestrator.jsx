// client/src/pages/ResponseOrchestrator.jsx

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';

import { useAuth } from '../context/AuthContext';
import {
  audit,
  orchestrator,
} from '../services/api';

const BLAST_COLOR = {
  LOW: '#34d399',
  MEDIUM: '#fbbf24',
  HIGH: '#fb923c',
  CRITICAL: '#f87171',
  UNKNOWN: '#94a3b8',
};

const STATUS_COLOR = {
  PENDING_APPROVAL: '#fbbf24',
  AUTO_EXECUTABLE: '#38bdf8',
  SIMULATED_SUCCESS: '#34d399',
  APPROVED: '#34d399',
  EXECUTED: '#34d399',
  REJECTED: '#f87171',
  FAILED: '#f87171',
  UNKNOWN: '#94a3b8',
};

const getIncidentId = (incident, index = 0) =>
  incident?.incident_id ||
  incident?.id ||
  `incident-${index}`;

const getActions = (incident) =>
  Array.isArray(incident?.actions)
    ? incident.actions
    : [];

const normaliseIncidents = (data) => {
  if (Array.isArray(data)) {
    return data;
  }

  if (Array.isArray(data?.incidents)) {
    return data.incidents;
  }

  if (Array.isArray(data?.items)) {
    return data.items;
  }

  return [];
};

const normaliseTrail = (data) => {
  if (Array.isArray(data)) {
    return data;
  }

  if (Array.isArray(data?.trail)) {
    return data.trail;
  }

  if (Array.isArray(data?.entries)) {
    return data.entries;
  }

  return [];
};

const formatDateTime = (value) => {
  if (!value) {
    return 'Time unavailable';
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
};

const formatTime = (value) => {
  if (!value) {
    return '—';
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleTimeString();
};

const formatConfidence = (value) => {
  const confidence = Number(value);

  if (!Number.isFinite(confidence)) {
    return 'Not available';
  }

  const percentage =
    confidence <= 1
      ? confidence * 100
      : confidence;

  return `${Math.round(percentage)}%`;
};

const formatLabel = (value, fallback = 'UNKNOWN') => {
  if (!value) {
    return fallback;
  }

  return String(value)
    .replace(/_/g, ' ')
    .trim();
};

export default function ResponseOrchestrator() {
  const { user } = useAuth();

  const [incidents, setIncidents] = useState([]);
  const [selected, setSelected] = useState(null);
  const [trail, setTrail] = useState([]);

  const [loading, setLoading] = useState(true);
  const [trailLoading, setTrailLoading] =
    useState(false);

  const [loadError, setLoadError] = useState('');
  const [actionError, setActionError] =
    useState('');

  const [busyAction, setBusyAction] =
    useState(null);

  const loadIncidents = useCallback(
    async ({ showLoading = false } = {}) => {
      if (showLoading) {
        setLoading(true);
      }

      try {
        const response =
          await orchestrator.list();

        const list = normaliseIncidents(
          response?.data,
        );

        setIncidents(list);
        setLoadError('');

        setSelected((currentSelected) => {
          if (list.length === 0) {
            return null;
          }

          const currentStillExists =
            list.some(
              (incident, index) =>
                getIncidentId(
                  incident,
                  index,
                ) === currentSelected,
            );

          if (
            currentSelected &&
            currentStillExists
          ) {
            return currentSelected;
          }

          return getIncidentId(
            list[0],
            0,
          );
        });
      } catch (error) {
        console.error(
          'Failed to load incidents:',
          error,
        );

        if (error?.response?.status === 404) {
          setLoadError(
            'The orchestrator route was not found. Check that /api/orchestrator/incidents is registered in the API gateway.',
          );
        } else if (
          error?.code === 'ECONNABORTED'
        ) {
          setLoadError(
            'The orchestrator request timed out.',
          );
        } else {
          setLoadError(
            'Could not load incidents. Confirm that the API gateway and FastAPI backend are running.',
          );
        }
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  const loadTrail = useCallback(
    async (incidentId) => {
      if (!incidentId) {
        setTrail([]);
        return;
      }

      setTrailLoading(true);

      try {
        const response =
          await audit.trail(incidentId);

        setTrail(
          normaliseTrail(response?.data),
        );
      } catch (error) {
        console.error(
          'Failed to load audit trail:',
          error,
        );

        setTrail([]);
      } finally {
        setTrailLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    loadIncidents({
      showLoading: true,
    });

    const intervalId = window.setInterval(
      () => {
        loadIncidents();
      },
      6000,
    );

    return () => {
      window.clearInterval(intervalId);
    };
  }, [loadIncidents]);

  useEffect(() => {
    loadTrail(selected);
  }, [selected, loadTrail]);

  const activeIncident = useMemo(
    () =>
      incidents.find(
        (incident, index) =>
          getIncidentId(
            incident,
            index,
          ) === selected,
      ) || null,
    [incidents, selected],
  );

  const activeActions =
    getActions(activeIncident);

  const handleDecision = async (
    incidentId,
    actionIndex,
    decision,
  ) => {
    const actionKey =
      `${incidentId}-${actionIndex}-${decision}`;

    setBusyAction(actionKey);
    setActionError('');

    try {
      await orchestrator.decide(
        incidentId,
        {
          approver:
            user?.username ||
            user?.name ||
            user?.email ||
            'analyst',
          decision,
          action_index: actionIndex,
        },
      );

      await loadIncidents();
      await loadTrail(incidentId);
    } catch (error) {
      console.error(
        'Decision failed:',
        error,
      );

      setActionError(
        error?.response?.data?.detail ||
        error?.response?.data?.message ||
        'The decision could not be recorded. Check the backend logs.',
      );
    } finally {
      setBusyAction(null);
    }
  };

  const handleAutoExecute = async (
    incidentId,
  ) => {
    const actionKey =
      `${incidentId}-auto-execute`;

    setBusyAction(actionKey);
    setActionError('');

    try {
      await orchestrator.autoExecute(
        incidentId,
      );

      await loadIncidents();
      await loadTrail(incidentId);
    } catch (error) {
      console.error(
        'Auto-execution failed:',
        error,
      );

      setActionError(
        error?.response?.data?.detail ||
        error?.response?.data?.message ||
        'The simulated low-risk actions could not be executed.',
      );
    } finally {
      setBusyAction(null);
    }
  };

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '24px',
        minWidth: 0,
      }}
    >
      <div className="fade-up">
        <h2
          style={{
            margin: 0,
            fontSize: '1.6rem',
            fontWeight: 800,
            color: 'var(--text-1)',
            letterSpacing: '-0.02em',
          }}
        >
          Response Orchestrator
        </h2>

        <p
          style={{
            marginTop: '6px',
            marginBottom: 0,
            fontSize: '0.9rem',
            lineHeight: 1.6,
            color: 'var(--text-3)',
          }}
        >
          Simulation Mode — recommended
          actions are not applied to live
          infrastructure. Medium-risk and
          high-risk actions require analyst
          approval.
        </p>
      </div>

      {loadError && (
        <div
          style={{
            padding: '13px 16px',
            borderRadius: '12px',
            background:
              'rgba(248,113,113,0.08)',
            border:
              '1px solid rgba(248,113,113,0.2)',
            color: '#f87171',
            fontSize: '0.84rem',
            lineHeight: 1.5,
          }}
        >
          {loadError}
        </div>
      )}

      {actionError && (
        <div
          style={{
            padding: '13px 16px',
            borderRadius: '12px',
            background:
              'rgba(251,146,60,0.08)',
            border:
              '1px solid rgba(251,146,60,0.2)',
            color: '#fb923c',
            fontSize: '0.84rem',
            lineHeight: 1.5,
          }}
        >
          {actionError}
        </div>
      )}

      <div
        style={{
          display: 'grid',
          gridTemplateColumns:
            'repeat(auto-fit, minmax(300px, 1fr))',
          gap: '20px',
          alignItems: 'start',
        }}
      >
        <section
          style={{
            minWidth: 0,
            background: 'var(--bg-card)',
            border:
              '1px solid var(--border)',
            borderRadius: '16px',
            padding: '18px',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent:
                'space-between',
              gap: '12px',
              marginBottom: '14px',
            }}
          >
            <h3
              style={{
                margin: 0,
                fontSize: '0.95rem',
                fontWeight: 700,
                color: 'var(--text-1)',
              }}
            >
              Incident Queue
            </h3>

            <span
              style={{
                padding: '4px 9px',
                borderRadius: '999px',
                background:
                  'rgba(56,189,248,0.1)',
                color: '#38bdf8',
                fontSize: '0.7rem',
                fontWeight: 700,
              }}
            >
              {incidents.length} total
            </span>
          </div>

          {loading && (
            <p
              style={{
                color: 'var(--text-3)',
                fontSize: '0.82rem',
              }}
            >
              Loading incidents...
            </p>
          )}

          {!loading &&
            incidents.length === 0 && (
              <div
                style={{
                  padding: '24px 14px',
                  borderRadius: '12px',
                  background:
                    'var(--bg-surface)',
                  border:
                    '1px solid var(--border)',
                  textAlign: 'center',
                }}
              >
                <div
                  style={{
                    color: 'var(--text-1)',
                    fontWeight: 700,
                    fontSize: '0.86rem',
                  }}
                >
                  No incidents available
                </div>

                <div
                  style={{
                    marginTop: '5px',
                    color: 'var(--text-3)',
                    fontSize: '0.76rem',
                    lineHeight: 1.5,
                  }}
                >
                  Trigger a supported detection
                  or create an incident through
                  the orchestrator API.
                </div>
              </div>
            )}

          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
              maxHeight: '650px',
              overflowY: 'auto',
            }}
          >
            {incidents.map(
              (incident, index) => {
                const incidentId =
                  getIncidentId(
                    incident,
                    index,
                  );

                const actions =
                  getActions(incident);

                const pendingCount =
                  actions.filter(
                    (action) =>
                      action?.status ===
                      'PENDING_APPROVAL',
                  ).length;

                const isSelected =
                  incidentId === selected;

                return (
                  <button
                    key={incidentId}
                    type="button"
                    onClick={() =>
                      setSelected(
                        incidentId,
                      )
                    }
                    style={{
                      width: '100%',
                      padding: '13px 14px',
                      borderRadius: '12px',
                      cursor: 'pointer',
                      textAlign: 'left',
                      background: isSelected
                        ? 'var(--cyan-dim)'
                        : 'var(--bg-surface)',
                      border: isSelected
                        ? '1px solid rgba(56,189,248,0.3)'
                        : '1px solid var(--border)',
                      color:
                        'var(--text-1)',
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        alignItems:
                          'flex-start',
                        justifyContent:
                          'space-between',
                        gap: '10px',
                      }}
                    >
                      <div
                        style={{
                          minWidth: 0,
                        }}
                      >
                        <div
                          style={{
                            overflow: 'hidden',
                            textOverflow:
                              'ellipsis',
                            whiteSpace: 'nowrap',
                            fontWeight: 700,
                            fontSize:
                              '0.82rem',
                          }}
                        >
                          {incidentId}
                        </div>

                        <div
                          style={{
                            marginTop: '3px',
                            overflow: 'hidden',
                            textOverflow:
                              'ellipsis',
                            whiteSpace: 'nowrap',
                            fontSize:
                              '0.73rem',
                            color:
                              'var(--text-3)',
                          }}
                        >
                          {incident
                            ?.detection
                            ?.target ||
                            incident?.target ||
                            'Unknown target'}
                        </div>
                      </div>

                      {pendingCount > 0 && (
                        <span
                          style={{
                            flexShrink: 0,
                            padding:
                              '3px 7px',
                            borderRadius:
                              '999px',
                            background:
                              'rgba(251,191,36,0.1)',
                            color:
                              '#fbbf24',
                            fontSize:
                              '0.65rem',
                            fontWeight: 700,
                          }}
                        >
                          {pendingCount}{' '}
                          pending
                        </span>
                      )}
                    </div>
                  </button>
                );
              },
            )}
          </div>
        </section>

        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '20px',
            minWidth: 0,
          }}
        >
          {activeIncident ? (
            <>
              <section
                style={{
                  minWidth: 0,
                  background:
                    'var(--bg-card)',
                  border:
                    '1px solid var(--border)',
                  borderRadius: '16px',
                  padding: '24px',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems:
                      'flex-start',
                    justifyContent:
                      'space-between',
                    flexWrap: 'wrap',
                    gap: '14px',
                  }}
                >
                  <div
                    style={{
                      minWidth: 0,
                    }}
                  >
                    <h3
                      style={{
                        margin: 0,
                        fontSize: '1.1rem',
                        fontWeight: 700,
                        color:
                          'var(--text-1)',
                        overflowWrap:
                          'anywhere',
                      }}
                    >
                      {getIncidentId(
                        activeIncident,
                      )}
                    </h3>

                    <p
                      style={{
                        marginTop: '5px',
                        marginBottom: 0,
                        color:
                          'var(--text-3)',
                        fontSize:
                          '0.82rem',
                        fontFamily:
                          'JetBrains Mono, monospace',
                        overflowWrap:
                          'anywhere',
                      }}
                    >
                      {activeIncident
                        ?.detection
                        ?.target ||
                        activeIncident
                          ?.target ||
                        'Unknown target'}
                    </p>
                  </div>

                  <span
                    style={{
                      color:
                        'var(--text-3)',
                      fontSize: '0.75rem',
                    }}
                  >
                    {formatDateTime(
                      activeIncident
                        ?.created_at ||
                      activeIncident
                        ?.timestamp,
                    )}
                  </span>
                </div>

                <div
                  style={{
                    display: 'flex',
                    flexWrap: 'wrap',
                    gap: '8px 18px',
                    marginTop: '14px',
                    color:
                      'var(--text-2)',
                    fontSize: '0.82rem',
                  }}
                >
                  <span>
                    Source:{' '}
                    <strong>
                      {activeIncident
                        ?.detection
                        ?.source ||
                        activeIncident
                          ?.source ||
                        'Unknown'}
                    </strong>
                  </span>

                  <span>
                    Confidence:{' '}
                    <strong>
                      {formatConfidence(
                        activeIncident
                          ?.detection
                          ?.confidence ??
                        activeIncident
                          ?.confidence,
                      )}
                    </strong>
                  </span>
                </div>

                <p
                  style={{
                    marginTop: '8px',
                    marginBottom: 0,
                    color:
                      'var(--text-3)',
                    fontSize: '0.8rem',
                    lineHeight: 1.6,
                    overflowWrap: 'anywhere',
                  }}
                >
                  {activeIncident
                    ?.detection?.reason ||
                    activeIncident?.reason ||
                    'No detection explanation was provided.'}
                </p>

                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px',
                    marginTop: '20px',
                  }}
                >
                  {activeActions.length ===
                    0 && (
                    <div
                      style={{
                        padding: '18px',
                        borderRadius:
                          '12px',
                        background:
                          'var(--bg-surface)',
                        border:
                          '1px solid var(--border)',
                        color:
                          'var(--text-3)',
                        fontSize:
                          '0.82rem',
                        textAlign:
                          'center',
                      }}
                    >
                      No recommended actions
                      were returned for this
                      incident.
                    </div>
                  )}

                  {activeActions.map(
                    (action, index) => {
                      const status =
                        String(
                          action?.status ||
                          'UNKNOWN',
                        ).toUpperCase();

                      const blastRadius =
                        String(
                          action
                            ?.blast_radius ||
                          'UNKNOWN',
                        ).toUpperCase();

                      const statusColor =
                        STATUS_COLOR[
                          status
                        ] ||
                        STATUS_COLOR.UNKNOWN;

                      const blastColor =
                        BLAST_COLOR[
                          blastRadius
                        ] ||
                        BLAST_COLOR.UNKNOWN;

                      const incidentId =
                        getIncidentId(
                          activeIncident,
                        );

                      const approveKey =
                        `${incidentId}-${index}-approve`;

                      const rejectKey =
                        `${incidentId}-${index}-reject`;

                      const isBusy =
                        busyAction ===
                          approveKey ||
                        busyAction ===
                          rejectKey;

                      return (
                        <div
                          key={
                            action
                              ?.action_id ||
                            `${incidentId}-${index}`
                          }
                          style={{
                            display: 'flex',
                            alignItems:
                              'center',
                            justifyContent:
                              'space-between',
                            flexWrap: 'wrap',
                            gap: '14px',
                            padding:
                              '15px 18px',
                            borderRadius:
                              '12px',
                            background:
                              'var(--bg-surface)',
                            border:
                              '1px solid var(--border)',
                          }}
                        >
                          <div
                            style={{
                              minWidth:
                                '180px',
                              flex: '1 1 220px',
                            }}
                          >
                            <div
                              style={{
                                color:
                                  'var(--text-1)',
                                fontWeight:
                                  700,
                                fontSize:
                                  '0.86rem',
                                overflowWrap:
                                  'anywhere',
                              }}
                            >
                              {action
                                ?.action ||
                                action
                                  ?.name ||
                                'Unnamed response action'}
                            </div>

                            <span
                              style={{
                                display:
                                  'inline-block',
                                marginTop:
                                  '4px',
                                color:
                                  blastColor,
                                fontSize:
                                  '0.71rem',
                                fontWeight:
                                  700,
                              }}
                            >
                              {formatLabel(
                                blastRadius,
                              )}{' '}
                              blast radius
                            </span>
                          </div>

                          <div
                            style={{
                              display:
                                'flex',
                              alignItems:
                                'center',
                              flexWrap:
                                'wrap',
                              gap: '9px',
                            }}
                          >
                            <span
                              style={{
                                padding:
                                  '5px 11px',
                                borderRadius:
                                  '999px',
                                background:
                                  `${statusColor}18`,
                                color:
                                  statusColor,
                                fontSize:
                                  '0.7rem',
                                fontWeight:
                                  700,
                              }}
                            >
                              {formatLabel(
                                status,
                              )}
                            </span>

                            {status ===
                              'PENDING_APPROVAL' && (
                              <>
                                <button
                                  type="button"
                                  disabled={
                                    isBusy
                                  }
                                  onClick={() =>
                                    handleDecision(
                                      incidentId,
                                      index,
                                      'approve',
                                    )
                                  }
                                  style={{
                                    padding:
                                      '7px 13px',
                                    borderRadius:
                                      '8px',
                                    border:
                                      '1px solid rgba(52,211,153,0.2)',
                                    background:
                                      'rgba(52,211,153,0.12)',
                                    color:
                                      '#34d399',
                                    fontWeight:
                                      700,
                                    fontSize:
                                      '0.75rem',
                                    cursor:
                                      isBusy
                                        ? 'not-allowed'
                                        : 'pointer',
                                    opacity:
                                      isBusy
                                        ? 0.6
                                        : 1,
                                  }}
                                >
                                  {busyAction ===
                                  approveKey
                                    ? 'Approving...'
                                    : 'Approve'}
                                </button>

                                <button
                                  type="button"
                                  disabled={
                                    isBusy
                                  }
                                  onClick={() =>
                                    handleDecision(
                                      incidentId,
                                      index,
                                      'reject',
                                    )
                                  }
                                  style={{
                                    padding:
                                      '7px 13px',
                                    borderRadius:
                                      '8px',
                                    border:
                                      '1px solid rgba(248,113,113,0.2)',
                                    background:
                                      'rgba(248,113,113,0.12)',
                                    color:
                                      '#f87171',
                                    fontWeight:
                                      700,
                                    fontSize:
                                      '0.75rem',
                                    cursor:
                                      isBusy
                                        ? 'not-allowed'
                                        : 'pointer',
                                    opacity:
                                      isBusy
                                        ? 0.6
                                        : 1,
                                  }}
                                >
                                  {busyAction ===
                                  rejectKey
                                    ? 'Rejecting...'
                                    : 'Reject'}
                                </button>
                              </>
                            )}
                          </div>
                        </div>
                      );
                    },
                  )}
                </div>

                {activeActions.some(
                  (action) =>
                    String(
                      action?.status,
                    ).toUpperCase() ===
                    'AUTO_EXECUTABLE',
                ) && (
                  <button
                    type="button"
                    disabled={
                      busyAction ===
                      `${getIncidentId(
                        activeIncident,
                      )}-auto-execute`
                    }
                    onClick={() =>
                      handleAutoExecute(
                        getIncidentId(
                          activeIncident,
                        ),
                      )
                    }
                    style={{
                      marginTop: '15px',
                      padding: '10px 18px',
                      borderRadius: '10px',
                      border: 'none',
                      background:
                        'linear-gradient(135deg, #38bdf8, #818cf8)',
                      color: '#ffffff',
                      fontWeight: 700,
                      fontSize: '0.8rem',
                      cursor:
                        busyAction
                          ? 'not-allowed'
                          : 'pointer',
                      opacity:
                        busyAction ===
                        `${getIncidentId(
                          activeIncident,
                        )}-auto-execute`
                          ? 0.65
                          : 1,
                    }}
                  >
                    {busyAction ===
                    `${getIncidentId(
                      activeIncident,
                    )}-auto-execute`
                      ? 'Executing simulation...'
                      : 'Execute approved low-risk actions'}
                  </button>
                )}
              </section>

              <section
                style={{
                  minWidth: 0,
                  background:
                    'var(--bg-card)',
                  border:
                    '1px solid var(--border)',
                  borderRadius: '16px',
                  padding: '24px',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    justifyContent:
                      'space-between',
                    alignItems: 'center',
                    gap: '12px',
                    marginBottom: '18px',
                  }}
                >
                  <h3
                    style={{
                      margin: 0,
                      fontSize: '1rem',
                      fontWeight: 700,
                      color:
                        'var(--text-1)',
                    }}
                  >
                    Audit Timeline
                  </h3>

                  <span
                    style={{
                      color:
                        'var(--text-3)',
                      fontSize: '0.72rem',
                    }}
                  >
                    {trail.length} entries
                  </span>
                </div>

                {trailLoading && (
                  <p
                    style={{
                      color:
                        'var(--text-3)',
                      fontSize: '0.82rem',
                    }}
                  >
                    Loading audit entries...
                  </p>
                )}

                {!trailLoading &&
                  trail.length === 0 && (
                    <p
                      style={{
                        color:
                          'var(--text-3)',
                        fontSize:
                          '0.84rem',
                      }}
                    >
                      No audit entries have
                      been recorded for this
                      incident yet.
                    </p>
                  )}

                {!trailLoading && (
                  <div
                    style={{
                      display: 'flex',
                      flexDirection:
                        'column',
                    }}
                  >
                    {trail.map(
                      (entry, index) => (
                        <div
                          key={
                            entry?.id ||
                            entry
                              ?.entry_id ||
                            `${entry?.created_at || 'entry'}-${index}`
                          }
                          style={{
                            display:
                              'flex',
                            gap: '14px',
                            paddingBottom:
                              '17px',
                          }}
                        >
                          <div
                            style={{
                              display:
                                'flex',
                              flexDirection:
                                'column',
                              alignItems:
                                'center',
                            }}
                          >
                            <div
                              style={{
                                width:
                                  '10px',
                                height:
                                  '10px',
                                borderRadius:
                                  '50%',
                                background:
                                  'var(--cyan)',
                                flexShrink: 0,
                              }}
                            />

                            {index <
                              trail.length -
                                1 && (
                              <div
                                style={{
                                  width:
                                    '2px',
                                  flex: 1,
                                  minHeight:
                                    '28px',
                                  marginTop:
                                    '3px',
                                  background:
                                    'var(--border)',
                                }}
                              />
                            )}
                          </div>

                          <div
                            style={{
                              minWidth: 0,
                            }}
                          >
                            <div
                              style={{
                                color:
                                  'var(--text-3)',
                                fontSize:
                                  '0.71rem',
                              }}
                            >
                              {formatTime(
                                entry
                                  ?.created_at ||
                                entry
                                  ?.timestamp,
                              )}
                            </div>

                            <div
                              style={{
                                marginTop:
                                  '2px',
                                color:
                                  'var(--text-1)',
                                fontSize:
                                  '0.85rem',
                                fontWeight:
                                  700,
                                overflowWrap:
                                  'anywhere',
                              }}
                            >
                              {formatLabel(
                                entry
                                  ?.action ||
                                entry
                                  ?.event,
                                'Audit event',
                              )}
                            </div>

                            <div
                              style={{
                                marginTop:
                                  '2px',
                                color:
                                  'var(--text-3)',
                                fontSize:
                                  '0.77rem',
                                lineHeight:
                                  1.5,
                                overflowWrap:
                                  'anywhere',
                              }}
                            >
                              by{' '}
                              {entry?.actor ||
                                entry?.user ||
                                'system'}
                              {(entry
                                ?.target ||
                                entry
                                  ?.resource) &&
                                ` — ${
                                  entry
                                    ?.target ||
                                  entry
                                    ?.resource
                                }`}
                            </div>
                          </div>
                        </div>
                      ),
                    )}
                  </div>
                )}
              </section>
            </>
          ) : (
            <section
              style={{
                minHeight: '220px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '40px',
                borderRadius: '16px',
                background: 'var(--bg-card)',
                border:
                  '1px solid var(--border)',
                color: 'var(--text-3)',
                textAlign: 'center',
                fontSize: '0.86rem',
              }}
            >
              {loading
                ? 'Loading incident information...'
                : 'Select an incident to view its response workflow.'}
            </section>
          )}
        </div>
      </div>
    </div>
  );
}