import { useMemo, useState } from 'react';
import {
  resilience,
  responseAutomation,
} from '../services/resilienceApi';
import './Resilience.css';

const DEMO_EVENTS = [
  {
    event_id: 'EVT-DEMO-001',
    timestamp: '2026-07-18T10:00:00+00:00',
    event_type: 'authentication',
    source_type: 'identity',
    organisation_id: 'ORG-DEMO-001',
    user_id: 'USR-104',
    device_id: 'DEV-018',
    asset_id: 'DEV-018',
    label: 'malicious',
    attributes: {
      authentication_result: 'success',
      unusual_login_time: true,
      source_country: 'unknown',
      failed_attempts_before_success: 8,
    },
  },
  {
    event_id: 'EVT-DEMO-002',
    timestamp: '2026-07-18T10:03:00+00:00',
    event_type: 'process_execution',
    source_type: 'endpoint',
    organisation_id: 'ORG-DEMO-001',
    user_id: 'USR-104',
    device_id: 'DEV-018',
    asset_id: 'DEV-018',
    label: 'malicious',
    attributes: {
      process_name: 'powershell.exe',
      encoded_command: true,
      parent_process: 'winword.exe',
    },
  },
  {
    event_id: 'EVT-DEMO-003',
    timestamp: '2026-07-18T10:06:00+00:00',
    event_type: 'credential_dumping',
    source_type: 'endpoint',
    organisation_id: 'ORG-DEMO-001',
    user_id: 'USR-104',
    device_id: 'DEV-018',
    asset_id: 'DEV-018',
    label: 'malicious',
    attributes: {
      target_process: 'lsass.exe',
      memory_access: true,
      credential_material_accessed: true,
    },
  },
  {
    event_id: 'EVT-DEMO-004',
    timestamp: '2026-07-18T10:10:00+00:00',
    event_type: 'account_discovery',
    source_type: 'endpoint',
    organisation_id: 'ORG-DEMO-001',
    user_id: 'USR-104',
    device_id: 'DEV-018',
    asset_id: 'DEV-018',
    label: 'malicious',
    attributes: {
      command: 'net user /domain',
      domain_enumeration: true,
    },
  },
];

function percentage(value) {
  const number = Number(value || 0);
  return `${(number * 100).toFixed(1)}%`;
}

function readable(value) {
  return String(value || '')
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (character) =>
      character.toUpperCase(),
    );
}

function statusClass(status) {
  switch (status) {
    case 'completed':
    case 'approved':
    case 'not_required':
      return 'resilience-badge success';

    case 'rejected':
    case 'failed':
      return 'resilience-badge danger';

    case 'pending':
    case 'pending_approval':
      return 'resilience-badge warning';

    default:
      return 'resilience-badge info';
  }
}

export default function Resilience() {
  const [incidentId, setIncidentId] = useState(
    `INC-DEMO-${Date.now()}`,
  );

  const [sourceNodeId, setSourceNodeId] =
    useState('DEV-018');

  const [eventText, setEventText] = useState(
    JSON.stringify(DEMO_EVENTS, null, 2),
  );

  const [result, setResult] = useState(null);
  const [execution, setExecution] = useState(null);
  const [auditRecords, setAuditRecords] = useState([]);
  const [auditVerification, setAuditVerification] =
    useState(null);

  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] =
    useState(false);

  const [error, setError] = useState('');
  const [approverId, setApproverId] = useState(
    'soc.analyst.one',
  );

  const pendingSteps = useMemo(() => {
    if (!execution?.steps) {
      return [];
    }

    return execution.steps.filter(
      (step) =>
        step.status === 'pending_approval',
    );
  }, [execution]);

  const loadDemo = () => {
    setIncidentId(`INC-DEMO-${Date.now()}`);
    setSourceNodeId('DEV-018');
    setEventText(
      JSON.stringify(DEMO_EVENTS, null, 2),
    );
    setError('');
  };

  const analyseIncident = async () => {
    setLoading(true);
    setError('');
    setResult(null);
    setExecution(null);
    setAuditRecords([]);
    setAuditVerification(null);

    try {
      const events = JSON.parse(eventText);

      if (!Array.isArray(events) || events.length === 0) {
        throw new Error(
          'Events must be a non-empty JSON array.',
        );
      }

      const response = await resilience.analyse({
        incident_id: incidentId,
        events,
        source_node_id:
          sourceNodeId.trim() || null,
        requested_by: 'cybershield.frontend',
        prediction_horizon: 3,
        maximum_recommendations: 5,
        auto_create_response: true,
      });

      setResult(response.data);
      setExecution(
        response.data.response_execution || null,
      );

      if (
        response.data.response_execution
          ?.execution_id
      ) {
        await refreshAudit(
          response.data.response_execution
            .execution_id,
        );
      }
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  };

  const refreshAudit = async (executionId) => {
    try {
      const [recordsResponse, verifyResponse] =
        await Promise.all([
          responseAutomation.executionAudit(
            executionId,
          ),
          responseAutomation.verifyAudit(),
        ]);

      setAuditRecords(recordsResponse.data || []);
      setAuditVerification(verifyResponse.data);
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  const submitDecision = async (
    step,
    approved,
  ) => {
    if (!execution) {
      return;
    }

    if (!approverId.trim()) {
      setError('Enter an approver ID.');
      return;
    }

    setActionLoading(true);
    setError('');

    try {
      const response =
        await responseAutomation.submitApproval(
          execution.execution_id,
          step.execution_step_id,
          approverId.trim(),
          approved,
          approved
            ? 'Approved after SOC investigation.'
            : 'Rejected after SOC investigation.',
        );

      setExecution(response.data);

      await refreshAudit(
        execution.execution_id,
      );
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setActionLoading(false);
    }
  };

  const executeResponse = async () => {
    if (!execution) {
      return;
    }

    setActionLoading(true);
    setError('');

    try {
      const response =
        await responseAutomation.execute(
          execution.execution_id,
        );

      setExecution(response.data);

      await refreshAudit(
        execution.execution_id,
      );
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="resilience-page">
      <section className="resilience-header">
        <div>
          <div className="resilience-eyebrow">
            Critical Infrastructure Intelligence
          </div>

          <h1>Cyber Resilience Command Center</h1>

          <p>
            Analyse attack behaviour, predict the next
            adversary stage, calculate blast radius,
            prioritise containment, and prepare a
            human-approved SOAR response.
          </p>
        </div>

        <div className="resilience-safety">
          <span className="resilience-safety-dot" />
          Simulation-only response
        </div>
      </section>

      {error && (
        <div className="resilience-error">
          <strong>Request failed:</strong> {error}
        </div>
      )}

      <section className="resilience-card">
        <div className="resilience-card-heading">
          <div>
            <h2>Incident analysis</h2>
            <p>
              Submit CNI telemetry to the complete
              resilience pipeline.
            </p>
          </div>

          <button
            type="button"
            className="resilience-button secondary"
            onClick={loadDemo}
          >
            Load Silent Intruder Demo
          </button>
        </div>

        <div className="resilience-form-grid">
          <label>
            Incident ID
            <input
              value={incidentId}
              onChange={(event) =>
                setIncidentId(event.target.value)
              }
            />
          </label>

          <label>
            Source asset
            <input
              value={sourceNodeId}
              onChange={(event) =>
                setSourceNodeId(event.target.value)
              }
              placeholder="DEV-018"
            />
          </label>
        </div>

        <label className="resilience-event-label">
          Security events
          <textarea
            value={eventText}
            onChange={(event) =>
              setEventText(event.target.value)
            }
            spellCheck={false}
          />
        </label>

        <button
          type="button"
          className="resilience-button primary"
          disabled={loading}
          onClick={analyseIncident}
        >
          {loading
            ? 'Running resilience analysis...'
            : 'Run End-to-End Analysis'}
        </button>
      </section>

      {result && (
        <>
          <section className="resilience-metrics">
            <article>
              <span>Severity</span>
              <strong>
                {readable(
                  result.decision?.severity,
                )}
              </strong>
            </article>

            <article>
              <span>Observed stage</span>
              <strong>
                {result.prediction
                  ?.current_tactic || 'Unknown'}
              </strong>
            </article>

            <article>
              <span>Predicted next stage</span>
              <strong>
                {result.prediction
                  ?.most_likely_next_tactic ||
                  'Unknown'}
              </strong>
            </article>

            <article>
              <span>Prediction confidence</span>
              <strong>
                {percentage(
                  result.prediction?.confidence,
                )}
              </strong>
            </article>
          </section>

          <div className="resilience-two-column">
            <section className="resilience-card">
              <div className="resilience-card-heading">
                <div>
                  <h2>Attack-stage prediction</h2>
                  <p>
                    Probable MITRE ATT&amp;CK progression.
                  </p>
                </div>
              </div>

              <div className="resilience-timeline">
                {(result.prediction
                  ?.predicted_stages || []
                ).map((stage) => (
                  <div
                    className="resilience-stage"
                    key={stage.sequence_number}
                  >
                    <div className="resilience-stage-number">
                      {stage.sequence_number}
                    </div>

                    <div>
                      <strong>{stage.tactic}</strong>
                      <span>
                        Stage probability:{' '}
                        {percentage(
                          stage.probability,
                        )}
                      </span>
                      <span>
                        Cumulative:{' '}
                        {percentage(
                          stage.cumulative_probability,
                        )}
                      </span>
                      <span>
                        Likely target:{' '}
                        {stage.likely_target_asset_id ||
                          'Not resolved'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section className="resilience-card">
              <div className="resilience-card-heading">
                <div>
                  <h2>Blast-radius intelligence</h2>
                  <p>
                    Architecture-aware compromise impact.
                  </p>
                </div>
              </div>

              {result.blast_radius ? (
                <div className="resilience-impact-grid">
                  <article>
                    <span>Reachable assets</span>
                    <strong>
                      {
                        result.blast_radius
                          .reachable_node_count
                      }
                    </strong>
                  </article>

                  <article>
                    <span>Critical assets</span>
                    <strong>
                      {
                        result.blast_radius
                          .critical_node_count
                      }
                    </strong>
                  </article>

                  <article>
                    <span>Maximum depth</span>
                    <strong>
                      {
                        result.blast_radius
                          .maximum_depth_reached
                      }
                    </strong>
                  </article>

                  <article>
                    <span>Blast score</span>
                    <strong>
                      {percentage(
                        result.blast_radius
                          .blast_radius_score,
                      )}
                    </strong>
                  </article>
                </div>
              ) : (
                <p className="resilience-muted">
                  Blast-radius data was unavailable.
                </p>
              )}

              <div className="resilience-target">
                Predicted target asset
                <strong>
                  {result.prediction
                    ?.most_likely_target_asset_id ||
                    'Not resolved'}
                </strong>
              </div>
            </section>
          </div>

          <section className="resilience-card">
            <div className="resilience-card-heading">
              <div>
                <h2>Prioritised remediation</h2>
                <p>
                  Ranked by blast-radius reduction and
                  operational effectiveness.
                </p>
              </div>
            </div>

            <div className="resilience-table-wrap">
              <table className="resilience-table">
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>Action</th>
                    <th>Target</th>
                    <th>Priority score</th>
                    <th>Risk reduction</th>
                  </tr>
                </thead>

                <tbody>
                  {(result.remediation_candidates || [])
                    .slice(0, 5)
                    .map((candidate, index) => (
                      <tr
                        key={
                          candidate.candidate_id ||
                          index
                        }
                      >
                        <td>{index + 1}</td>
                        <td>
                          {readable(
                            candidate.action_type,
                          )}
                        </td>
                        <td>
                          {candidate.target_node_id ||
                            candidate.target_edge_id ||
                            'Not specified'}
                        </td>
                        <td>
                          {Number(
                            candidate.priority_score ||
                              0,
                          ).toFixed(4)}
                        </td>
                        <td>
                          {percentage(
                            candidate
                              .blast_radius_reduction,
                          )}
                        </td>
                      </tr>
                    ))}

                  {!result.remediation_candidates
                    ?.length && (
                    <tr>
                      <td colSpan="5">
                        No remediation candidates
                        returned.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <div className="resilience-two-column">
            <section className="resilience-card">
              <div className="resilience-card-heading">
                <div>
                  <h2>Recommended SOAR response</h2>
                  <p>
                    Human-gated containment preparation.
                  </p>
                </div>

                {execution && (
                  <span
                    className={statusClass(
                      execution.status,
                    )}
                  >
                    {readable(execution.status)}
                  </span>
                )}
              </div>

              <div className="resilience-playbook">
                <span>Selected playbook</span>
                <strong>
                  {result.decision
                    ?.recommended_playbook_name ||
                    'No playbook selected'}
                </strong>
                <small>
                  {result.decision
                    ?.recommended_playbook_id}
                </small>
              </div>

              {execution && (
                <>
                  <label className="resilience-approver">
                    Analyst identity
                    <input
                      value={approverId}
                      onChange={(event) =>
                        setApproverId(
                          event.target.value,
                        )
                      }
                    />
                  </label>

                  <div className="resilience-step-list">
                    {execution.steps.map((step) => (
                      <article
                        key={
                          step.execution_step_id
                        }
                      >
                        <div>
                          <strong>
                            {step.step_number}.{' '}
                            {readable(
                              step.action_type,
                            )}
                          </strong>

                          <small>
                            {
                              step.execution_step_id
                            }
                          </small>
                        </div>

                        <div className="resilience-step-actions">
                          <span
                            className={statusClass(
                              step.status,
                            )}
                          >
                            {readable(step.status)}
                          </span>

                          {step.status ===
                            'pending_approval' && (
                            <>
                              <button
                                type="button"
                                disabled={
                                  actionLoading
                                }
                                className="resilience-mini-button approve"
                                onClick={() =>
                                  submitDecision(
                                    step,
                                    true,
                                  )
                                }
                              >
                                Approve
                              </button>

                              <button
                                type="button"
                                disabled={
                                  actionLoading
                                }
                                className="resilience-mini-button reject"
                                onClick={() =>
                                  submitDecision(
                                    step,
                                    false,
                                  )
                                }
                              >
                                Reject
                              </button>
                            </>
                          )}
                        </div>
                      </article>
                    ))}
                  </div>

                  <button
                    type="button"
                    className="resilience-button primary"
                    disabled={
                      actionLoading ||
                      execution.status ===
                        'completed' ||
                      execution.status ===
                        'rejected'
                    }
                    onClick={executeResponse}
                  >
                    {actionLoading
                      ? 'Processing...'
                      : pendingSteps.length
                        ? 'Execute Approved Automatic Steps'
                        : 'Execute Approved Response'}
                  </button>
                </>
              )}
            </section>

            <section className="resilience-card">
              <div className="resilience-card-heading">
                <div>
                  <h2>Audit integrity</h2>
                  <p>
                    SHA-256 chained evidence ledger.
                  </p>
                </div>

                {auditVerification && (
                  <span
                    className={
                      auditVerification.valid
                        ? 'resilience-badge success'
                        : 'resilience-badge danger'
                    }
                  >
                    {auditVerification.valid
                      ? 'Chain Valid'
                      : 'Integrity Failed'}
                  </span>
                )}
              </div>

              <div className="resilience-audit-list">
                {auditRecords.map((record) => (
                  <article key={record.record_id}>
                    <div>
                      <strong>
                        {readable(record.event_type)}
                      </strong>
                      <span>
                        {record.actor_id}
                      </span>
                    </div>

                    <small>
                      #{record.sequence_number} ·{' '}
                      {new Date(
                        record.timestamp,
                      ).toLocaleString()}
                    </small>
                  </article>
                ))}

                {!auditRecords.length && (
                  <p className="resilience-muted">
                    Audit records will appear after
                    response preparation.
                  </p>
                )}
              </div>
            </section>
          </div>

          <section className="resilience-card">
            <div className="resilience-card-heading">
              <div>
                <h2>Pipeline evidence</h2>
                <p>
                  Completed backend intelligence stages.
                </p>
              </div>
            </div>

            <div className="resilience-pipeline-list">
              {(result.pipeline_steps || []).map(
                (step, index) => (
                  <div key={step}>
                    <span>{index + 1}</span>
                    {step}
                  </div>
                ),
              )}
            </div>
          </section>
        </>
      )}
    </div>
  );
}