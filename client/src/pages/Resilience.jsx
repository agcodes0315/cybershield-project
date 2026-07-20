import {
  useMemo,
  useRef,
  useState,
} from 'react';

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

function extractErrorMessage(requestError) {
  return (
    requestError?.response?.data?.detail ||
    requestError?.response?.data?.error ||
    requestError?.response?.data?.message ||
    requestError?.message ||
    'The request could not be completed.'
  );
}

function getAuditIdentity(record) {
  return (
    record.record_id ||
    record.hash ||
    [
      record.sequence_number,
      record.event_type,
      record.actor_id,
      record.timestamp,
      record.execution_step_id,
    ]
      .filter(Boolean)
      .join('|')
  );
}

function getAuditDescription(record) {
  const actionType =
    record.action_type ||
    record.details?.action_type ||
    record.metadata?.action_type ||
    record.payload?.action_type;

  const stepNumber =
    record.step_number ||
    record.details?.step_number ||
    record.metadata?.step_number ||
    record.payload?.step_number;

  if (actionType && stepNumber) {
    return `Step ${stepNumber}: ${readable(actionType)}`;
  }

  if (actionType) {
    return readable(actionType);
  }

  return '';
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

  const [auditRecords, setAuditRecords] =
    useState([]);

  const [
    auditVerification,
    setAuditVerification,
  ] = useState(null);

  const [loading, setLoading] = useState(false);

  const [actionLoading, setActionLoading] =
    useState(false);

  const [executionAttempted, setExecutionAttempted] =
    useState(false);

  const [error, setError] = useState('');

  const [approverId, setApproverId] = useState(
    'soc.analyst.one',
  );

  /*
   * This synchronous ref prevents two clicks from
   * starting two API requests before React finishes
   * updating actionLoading.
   */
  const actionLockRef = useRef(false);

  const pendingSteps = useMemo(() => {
    if (!execution?.steps) {
      return [];
    }

    return execution.steps.filter(
      (step) =>
        step.status === 'pending_approval',
    );
  }, [execution]);

  const approvedSteps = useMemo(() => {
    if (!execution?.steps) {
      return [];
    }

    return execution.steps.filter(
      (step) => step.status === 'approved',
    );
  }, [execution]);

  const completedSteps = useMemo(() => {
    if (!execution?.steps) {
      return [];
    }

    return execution.steps.filter(
      (step) => step.status === 'completed',
    );
  }, [execution]);

  const rejectedSteps = useMemo(() => {
    if (!execution?.steps) {
      return [];
    }

    return execution.steps.filter(
      (step) => step.status === 'rejected',
    );
  }, [execution]);

  /*
   * Deduplicates only records that are genuinely the
   * same backend audit record.
   *
   * It does not collapse four legitimate Step Completed
   * records belonging to four different playbook steps.
   */
  const uniqueAuditRecords = useMemo(() => {
    const uniqueRecords = new Map();

    for (const record of auditRecords) {
      const identity = getAuditIdentity(record);

      if (!uniqueRecords.has(identity)) {
        uniqueRecords.set(identity, record);
      }
    }

    return Array.from(
      uniqueRecords.values(),
    ).sort(
      (firstRecord, secondRecord) =>
        Number(
          firstRecord.sequence_number || 0,
        ) -
        Number(
          secondRecord.sequence_number || 0,
        ),
    );
  }, [auditRecords]);

  const hasPendingHumanDecisions =
    pendingSteps.length > 0;

  const hasApprovedSteps =
    approvedSteps.length > 0;

  const executionFinished =
    execution?.status === 'completed' ||
    execution?.status === 'rejected' ||
    execution?.status === 'failed';

  /*
   * Important workflow:
   *
   * 1. Resolve every human-gated decision.
   * 2. Execute the complete approved response once.
   *
   * This prevents automatic steps from executing once
   * before approval and then executing again afterward.
   */
  const canExecuteResponse =
    Boolean(execution) &&
    !actionLoading &&
    !executionAttempted &&
    !executionFinished &&
    !hasPendingHumanDecisions &&
    hasApprovedSteps;

  const resetActionState = () => {
    actionLockRef.current = false;
    setActionLoading(false);
  };

  const loadDemo = () => {
    setIncidentId(`INC-DEMO-${Date.now()}`);
    setSourceNodeId('DEV-018');

    setEventText(
      JSON.stringify(DEMO_EVENTS, null, 2),
    );

    setResult(null);
    setExecution(null);
    setAuditRecords([]);
    setAuditVerification(null);
    setExecutionAttempted(false);
    setError('');

    actionLockRef.current = false;
  };

  const refreshAudit = async (executionId) => {
    if (!executionId) {
      return;
    }

    try {
      const [
        recordsResponse,
        verifyResponse,
      ] = await Promise.all([
        responseAutomation.executionAudit(
          executionId,
        ),
        responseAutomation.verifyAudit(),
      ]);

      const receivedRecords = Array.isArray(
        recordsResponse.data,
      )
        ? recordsResponse.data
        : [];

      setAuditRecords(receivedRecords);
      setAuditVerification(verifyResponse.data);
    } catch (requestError) {
      setError(
        extractErrorMessage(requestError),
      );
    }
  };

  const analyseIncident = async () => {
    if (loading || actionLockRef.current) {
      return;
    }

    actionLockRef.current = true;

    setLoading(true);
    setError('');
    setResult(null);
    setExecution(null);
    setAuditRecords([]);
    setAuditVerification(null);
    setExecutionAttempted(false);

    try {
      const events = JSON.parse(eventText);

      if (
        !Array.isArray(events) ||
        events.length === 0
      ) {
        throw new Error(
          'Events must be a non-empty JSON array.',
        );
      }

      const response = await resilience.analyse({
        incident_id: incidentId.trim(),
        events,
        source_node_id:
          sourceNodeId.trim() || null,
        requested_by:
          'cybershield.frontend',
        prediction_horizon: 3,
        maximum_recommendations: 5,
        auto_create_response: true,
      });

      const responseData = response.data;
      const responseExecution =
        responseData.response_execution || null;

      setResult(responseData);
      setExecution(responseExecution);

      if (responseExecution?.execution_id) {
        await refreshAudit(
          responseExecution.execution_id,
        );
      }
    } catch (requestError) {
      setError(
        extractErrorMessage(requestError),
      );
    } finally {
      actionLockRef.current = false;
      setLoading(false);
    }
  };

  const submitDecision = async (
    step,
    approved,
  ) => {
    if (
      !execution ||
      actionLoading ||
      actionLockRef.current
    ) {
      return;
    }

    if (
      step.status !== 'pending_approval'
    ) {
      return;
    }

    if (!approverId.trim()) {
      setError('Enter an approver ID.');
      return;
    }

    actionLockRef.current = true;
    setActionLoading(true);
    setError('');

    const executionId =
      execution.execution_id;

    try {
      const response =
        await responseAutomation.submitApproval(
          executionId,
          step.execution_step_id,
          approverId.trim(),
          approved,
          approved
            ? 'Approved after SOC investigation.'
            : 'Rejected after SOC investigation.',
        );

      setExecution(response.data);

      await refreshAudit(executionId);
    } catch (requestError) {
      setError(
        extractErrorMessage(requestError),
      );
    } finally {
      resetActionState();
    }
  };

  const executeResponse = async () => {
    if (
      !execution ||
      actionLoading ||
      actionLockRef.current
    ) {
      return;
    }

    if (pendingSteps.length > 0) {
      setError(
        'Approve or reject every pending human-gated step before executing the response.',
      );

      return;
    }

    if (!approvedSteps.length) {
      setError(
        'There are no approved steps available for execution.',
      );

      return;
    }

    if (
      executionAttempted ||
      executionFinished
    ) {
      setError(
        'This response has already been executed. Load a new demo to create another execution.',
      );

      return;
    }

    actionLockRef.current = true;
    setActionLoading(true);
    setExecutionAttempted(true);
    setError('');

    const executionId =
      execution.execution_id;

    try {
      const response =
        await responseAutomation.execute(
          executionId,
        );

      setExecution(response.data);

      await refreshAudit(executionId);
    } catch (requestError) {
      /*
       * Permit retry only when the request failed.
       */
      setExecutionAttempted(false);

      setError(
        extractErrorMessage(requestError),
      );
    } finally {
      resetActionState();
    }
  };

  const getExecuteButtonText = () => {
    if (actionLoading) {
      return 'Executing Approved Response...';
    }

    if (executionFinished) {
      return 'Response Execution Completed';
    }

    if (executionAttempted) {
      return 'Response Already Executed';
    }

    if (hasPendingHumanDecisions) {
      return `Resolve ${pendingSteps.length} Human Approval${
        pendingSteps.length === 1 ? '' : 's'
      } First`;
    }

    if (!hasApprovedSteps) {
      return 'No Approved Steps Available';
    }

    return 'Execute Approved Response Once';
  };

  return (
    <div className="resilience-page">
      <section className="resilience-header">
        <div>
          <div className="resilience-eyebrow">
            Critical Infrastructure Intelligence
          </div>

          <h1>
            Cyber Resilience Command Center
          </h1>

          <p>
            Analyse attack behaviour, predict the
            next adversary stage, calculate blast
            radius, prioritise containment, and
            prepare a human-approved SOAR response.
          </p>
        </div>

        <div className="resilience-safety">
          <span className="resilience-safety-dot" />
          Simulation-only response
        </div>
      </section>

      {error && (
        <div className="resilience-error">
          <strong>Request failed:</strong>{' '}
          {error}
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
            disabled={loading || actionLoading}
          >
            Load Silent Intruder Demo
          </button>
        </div>

        <div className="resilience-form-grid">
          <label>
            Incident ID

            <input
              value={incidentId}
              disabled={loading || actionLoading}
              onChange={(event) =>
                setIncidentId(
                  event.target.value,
                )
              }
            />
          </label>

          <label>
            Source asset

            <input
              value={sourceNodeId}
              disabled={loading || actionLoading}
              onChange={(event) =>
                setSourceNodeId(
                  event.target.value,
                )
              }
              placeholder="DEV-018"
            />
          </label>
        </div>

        <label className="resilience-event-label">
          Security events

          <textarea
            value={eventText}
            disabled={loading || actionLoading}
            onChange={(event) =>
              setEventText(
                event.target.value,
              )
            }
            spellCheck={false}
          />
        </label>

        <button
          type="button"
          className="resilience-button primary"
          disabled={loading || actionLoading}
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
                  ?.current_tactic ||
                  'Unknown'}
              </strong>
            </article>

            <article>
              <span>
                Predicted next stage
              </span>

              <strong>
                {result.prediction
                  ?.most_likely_next_tactic ||
                  'Unknown'}
              </strong>
            </article>

            <article>
              <span>
                Prediction confidence
              </span>

              <strong>
                {percentage(
                  result.prediction
                    ?.confidence,
                )}
              </strong>
            </article>
          </section>

          <div className="resilience-two-column">
            <section className="resilience-card">
              <div className="resilience-card-heading">
                <div>
                  <h2>
                    Attack-stage prediction
                  </h2>

                  <p>
                    Probable MITRE ATT&amp;CK
                    progression.
                  </p>
                </div>
              </div>

              <div className="resilience-timeline">
                {(result.prediction
                  ?.predicted_stages || []
                ).map((stage) => (
                  <div
                    className="resilience-stage"
                    key={
                      stage.sequence_number
                    }
                  >
                    <div className="resilience-stage-number">
                      {stage.sequence_number}
                    </div>

                    <div>
                      <strong>
                        {stage.tactic}
                      </strong>

                      <span>
                        Stage probability:{' '}
                        {percentage(
                          stage.probability,
                        )}
                      </span>

                      <span>
                        Cumulative:{' '}
                        {percentage(
                          stage
                            .cumulative_probability,
                        )}
                      </span>

                      <span>
                        Likely target:{' '}
                        {stage
                          .likely_target_asset_id ||
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
                  <h2>
                    Blast-radius intelligence
                  </h2>

                  <p>
                    Architecture-aware compromise
                    impact.
                  </p>
                </div>
              </div>

              {result.blast_radius ? (
                <div className="resilience-impact-grid">
                  <article>
                    <span>
                      Reachable assets
                    </span>

                    <strong>
                      {result.blast_radius
                        .reachable_node_count ??
                        0}
                    </strong>
                  </article>

                  <article>
                    <span>
                      Critical assets
                    </span>

                    <strong>
                      {result.blast_radius
                        .critical_node_count ??
                        0}
                    </strong>
                  </article>

                  <article>
                    <span>
                      Maximum depth
                    </span>

                    <strong>
                      {result.blast_radius
                        .maximum_depth_reached ??
                        'Not available'}
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
                  Blast-radius data was
                  unavailable.
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
                <h2>
                  Prioritised remediation
                </h2>

                <p>
                  Ranked by blast-radius
                  reduction and operational
                  effectiveness.
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
                  {(result
                    .remediation_candidates ||
                    []
                  )
                    .slice(0, 5)
                    .map(
                      (
                        candidate,
                        index,
                      ) => (
                        <tr
                          key={
                            candidate
                              .candidate_id ||
                            `${candidate.action_type}-${index}`
                          }
                        >
                          <td>
                            {index + 1}
                          </td>

                          <td>
                            {readable(
                              candidate
                                .action_type,
                            )}
                          </td>

                          <td>
                            {candidate
                              .target_node_id ||
                              candidate
                                .target_edge_id ||
                              'Not specified'}
                          </td>

                          <td>
                            {Number(
                              candidate
                                .priority_score ||
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
                      ),
                    )}

                  {!result
                    .remediation_candidates
                    ?.length && (
                    <tr>
                      <td colSpan="5">
                        No remediation
                        candidates returned.
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
                  <h2>
                    Recommended SOAR response
                  </h2>

                  <p>
                    Human-gated containment
                    preparation.
                  </p>
                </div>

                {execution && (
                  <span
                    className={statusClass(
                      execution.status,
                    )}
                  >
                    {readable(
                      execution.status,
                    )}
                  </span>
                )}
              </div>

              <div className="resilience-playbook">
                <span>
                  Selected playbook
                </span>

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
                      disabled={actionLoading}
                      onChange={(event) =>
                        setApproverId(
                          event.target.value,
                        )
                      }
                    />
                  </label>

                  {pendingSteps.length > 0 && (
                    <div className="resilience-error">
                      <strong>
                        Human approval required:
                      </strong>{' '}
                      resolve all{' '}
                      {pendingSteps.length}{' '}
                      pending step
                      {pendingSteps.length === 1
                        ? ''
                        : 's'}{' '}
                      before executing the
                      response.
                    </div>
                  )}

                  <div className="resilience-step-list">
                    {execution.steps.map(
                      (step) => (
                        <article
                          key={
                            step
                              .execution_step_id
                          }
                        >
                          <div>
                            <strong>
                              {
                                step.step_number
                              }
                              .{' '}
                              {readable(
                                step
                                  .action_type,
                              )}
                            </strong>

                            <small>
                              {
                                step
                                  .execution_step_id
                              }
                            </small>
                          </div>

                          <div className="resilience-step-actions">
                            <span
                              className={statusClass(
                                step.status,
                              )}
                            >
                              {readable(
                                step.status,
                              )}
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
                      ),
                    )}
                  </div>

                  <button
                    type="button"
                    className="resilience-button primary"
                    disabled={!canExecuteResponse}
                    onClick={executeResponse}
                  >
                    {getExecuteButtonText()}
                  </button>

                  <p className="resilience-muted">
                    Approved: {approvedSteps.length}
                    {' · '}
                    Pending approval:{' '}
                    {pendingSteps.length}
                    {' · '}
                    Completed:{' '}
                    {completedSteps.length}
                    {' · '}
                    Rejected:{' '}
                    {rejectedSteps.length}
                  </p>
                </>
              )}
            </section>

            <section className="resilience-card">
              <div className="resilience-card-heading">
                <div>
                  <h2>Audit integrity</h2>

                  <p>
                    SHA-256 chained evidence
                    ledger.
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
                {uniqueAuditRecords.map(
                  (record) => {
                    const description =
                      getAuditDescription(
                        record,
                      );

                    return (
                      <article
                        key={getAuditIdentity(
                          record,
                        )}
                      >
                        <div>
                          <strong>
                            {readable(
                              record.event_type,
                            )}
                          </strong>

                          <span>
                            {record.actor_id ||
                              'Unknown actor'}
                          </span>
                        </div>

                        {description && (
                          <span>
                            {description}
                          </span>
                        )}

                        <small>
                          #
                          {record.sequence_number}
                          {' · '}
                          {new Date(
                            record.timestamp,
                          ).toLocaleString()}
                        </small>
                      </article>
                    );
                  },
                )}

                {!uniqueAuditRecords.length && (
                  <p className="resilience-muted">
                    Audit records will appear
                    after response preparation.
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
                  Completed backend
                  intelligence stages.
                </p>
              </div>
            </div>

            <div className="resilience-pipeline-list">
              {(result.pipeline_steps || []).map(
                (step, index) => (
                  <div
                    key={`${index}-${step}`}
                  >
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