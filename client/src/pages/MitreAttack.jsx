import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  mitre,
  threats,
} from "../services/api";

import "./MitreAttack.css";

const TACTIC_ORDER = [
  "Reconnaissance",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
  "Unknown",
];

const EMPTY_SUMMARY = {
  mapping_coverage: 0,
  threat_records: 0,
  technique_count: 0,
  tactic_count: 0,
  critical_mappings: 0,
};

function normaliseText(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function getSeverityClass(severity) {
  const value =
    normaliseText(severity);

  if (value === "critical") {
    return "mitre-severity-critical";
  }

  if (value === "high") {
    return "mitre-severity-high";
  }

  if (value === "medium") {
    return "mitre-severity-medium";
  }

  return "mitre-severity-low";
}

function formatDate(value) {
  if (!value) {
    return "Not available";
  }

  const date = new Date(value);

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return String(value);
  }

  return date.toLocaleString();
}

function formatConfidence(value) {
  const number =
    Number(value || 0);

  if (!Number.isFinite(number)) {
    return "0%";
  }

  if (
    number > 0 &&
    number <= 1
  ) {
    return `${Math.round(
      number * 100,
    )}%`;
  }

  return `${Math.round(
    Math.min(
      Math.max(number, 0),
      100,
    ),
  )}%`;
}

function normaliseIndicator(
  indicator,
  index,
  technique,
) {
  return {
    id:
      indicator?.id ||
      `${technique}-${index}`,
    url:
      indicator?.url ||
      indicator?.indicator ||
      "Unknown indicator",
    source:
      indicator?.source ||
      "Unknown",
    threat_type:
      indicator?.threat_type ||
      indicator?.type ||
      "Unknown",
    confidence:
      Number(
        indicator?.confidence,
      ) || 0,
    last_seen:
      indicator?.last_seen ||
      null,
  };
}

function normaliseTechnique(
  item,
  index,
) {
  const indicators =
    Array.isArray(
      item?.indicators,
    )
      ? item.indicators.map(
          (
            indicator,
            indicatorIndex,
          ) =>
            normaliseIndicator(
              indicator,
              indicatorIndex,
              item?.technique ||
                `technique-${index}`,
            ),
        )
      : [];

  return {
    id:
      `${item?.tactic || "Unknown"}-${
        item?.technique ||
        `technique-${index}`
      }`,
    tactic:
      item?.tactic ||
      "Unknown",
    technique:
      item?.technique ||
      "N/A",
    name:
      item?.name ||
      "Unmapped Threat Activity",
    severity:
      item?.severity ||
      "Low",
    count:
      Number(item?.count) ||
      indicators.length,
    average_confidence:
      Number(
        item?.average_confidence,
      ) || 0,
    highest_confidence:
      Number(
        item?.highest_confidence,
      ) || 0,
    last_seen:
      item?.last_seen ||
      null,
    sources:
      Array.isArray(
        item?.sources,
      )
        ? item.sources
        : [],
    indicators,
  };
}

export default function MitreAttack() {
  const [
    techniques,
    setTechniques,
  ] = useState([]);

  const [
    summary,
    setSummary,
  ] = useState(
    EMPTY_SUMMARY,
  );

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    refreshing,
    setRefreshing,
  ] = useState(false);

  const [
    error,
    setError,
  ] = useState("");

  const [
    successMessage,
    setSuccessMessage,
  ] = useState("");

  const [
    searchTerm,
    setSearchTerm,
  ] = useState("");

  const [
    tacticFilter,
    setTacticFilter,
  ] = useState("All");

  const [
    severityFilter,
    setSeverityFilter,
  ] = useState("All");

  const [
    selectedTechnique,
    setSelectedTechnique,
  ] = useState(null);

  const [
    selectedIndicator,
    setSelectedIndicator,
  ] = useState(null);

  const loadMappings =
    useCallback(
      async (
        showRefreshState = false,
      ) => {
        try {
          if (showRefreshState) {
            setRefreshing(true);
          } else {
            setLoading(true);
          }

          setError("");
          setSuccessMessage("");

          /*
           * Normal page load:
           * GET /api/mitre
           *
           * Refresh button:
           * POST /api/threats/fetch
           * then GET /api/mitre
           */
          if (showRefreshState) {
            await threats.fetchFeeds();
          }

          const response =
            await mitre.getMappings();

          const payload =
            response?.data || {};

          const records =
            Array.isArray(
              payload.techniques,
            )
              ? payload.techniques.map(
                  normaliseTechnique,
                )
              : [];

          const backendSummary =
            payload?.summary &&
            typeof payload.summary ===
              "object"
              ? payload.summary
              : {};

          setTechniques(records);

          setSummary({
            mapping_coverage:
              Number(
                backendSummary.mapping_coverage,
              ) || 0,

            threat_records:
              Number(
                backendSummary.threat_records,
              ) || 0,

            technique_count:
              Number(
                backendSummary.technique_count,
              ) || 0,

            tactic_count:
              Number(
                backendSummary.tactic_count,
              ) || 0,

            critical_mappings:
              Number(
                backendSummary.critical_mappings,
              ) || 0,
          });

          setSelectedTechnique(
            (current) => {
              if (
                records.length === 0
              ) {
                return null;
              }

              if (!current) {
                return records[0];
              }

              return (
                records.find(
                  (item) =>
                    item.id ===
                    current.id,
                ) ||
                records[0]
              );
            },
          );

          if (showRefreshState) {
            setSuccessMessage(
              "Threat feeds and MITRE ATT&CK mappings refreshed successfully.",
            );
          }
        } catch (
          requestError
        ) {
          console.error(
            "[MITRE PAGE ERROR]",
            requestError,
          );

          setError(
            requestError
              ?.response?.data
              ?.error ||
              "Unable to load MITRE ATT&CK mappings.",
          );

          if (
            !showRefreshState
          ) {
            setTechniques([]);
            setSummary(
              EMPTY_SUMMARY,
            );
            setSelectedTechnique(
              null,
            );
            setSelectedIndicator(
              null,
            );
          }
        } finally {
          setLoading(false);
          setRefreshing(false);
        }
      },
      [],
    );

  useEffect(() => {
    loadMappings(false);
  }, [loadMappings]);

  useEffect(() => {
    if (
      !selectedTechnique
    ) {
      setSelectedIndicator(
        null,
      );
      return;
    }

    setSelectedIndicator(
      selectedTechnique
        .indicators?.[0] ||
        null,
    );
  }, [selectedTechnique]);

  const tactics = useMemo(
    () => {
      const unique =
        Array.from(
          new Set(
            techniques.map(
              (item) =>
                item.tactic ||
                "Unknown",
            ),
          ),
        );

      return unique.sort(
        (first, second) => {
          const firstIndex =
            TACTIC_ORDER.indexOf(
              first,
            );

          const secondIndex =
            TACTIC_ORDER.indexOf(
              second,
            );

          if (
            firstIndex === -1 &&
            secondIndex === -1
          ) {
            return first.localeCompare(
              second,
            );
          }

          if (
            firstIndex === -1
          ) {
            return 1;
          }

          if (
            secondIndex === -1
          ) {
            return -1;
          }

          return (
            firstIndex -
            secondIndex
          );
        },
      );
    },
    [techniques],
  );

  const filteredTechniques =
    useMemo(() => {
      const search =
        normaliseText(
          searchTerm,
        );

      return techniques.filter(
        (item) => {
          const indicatorText =
            item.indicators
              .map(
                (indicator) =>
                  [
                    indicator.url,
                    indicator.source,
                    indicator.threat_type,
                  ].join(" "),
              )
              .join(" ");

          const matchesSearch =
            !search ||
            [
              item.technique,
              item.name,
              item.tactic,
              item.severity,
              item.sources.join(
                " ",
              ),
              indicatorText,
            ].some((value) =>
              normaliseText(
                value,
              ).includes(search),
            );

          const matchesTactic =
            tacticFilter ===
              "All" ||
            item.tactic ===
              tacticFilter;

          const matchesSeverity =
            severityFilter ===
              "All" ||
            normaliseText(
              item.severity,
            ) ===
              normaliseText(
                severityFilter,
              );

          return (
            matchesSearch &&
            matchesTactic &&
            matchesSeverity
          );
        },
      );
    }, [
      techniques,
      searchTerm,
      tacticFilter,
      severityFilter,
    ]);

  const groupedTechniques =
    useMemo(() => {
      return tactics
        .map((tactic) => ({
          tactic,
          records:
            filteredTechniques.filter(
              (item) =>
                item.tactic ===
                tactic,
            ),
        }))
        .filter(
          (group) =>
            group.records.length >
            0,
        );
    }, [
      tactics,
      filteredTechniques,
    ]);

  function clearFilters() {
    setSearchTerm("");
    setTacticFilter("All");
    setSeverityFilter("All");
  }

  return (
    <main className="mitre-page">
      <section className="mitre-header">
        <div>
          <span className="mitre-eyebrow">
            CyberShield SOC
          </span>

          <h1>
            MITRE ATT&amp;CK Centre
          </h1>

          <p>
            Review aggregated threat
            techniques and inspect the
            indicators associated with
            each MITRE ATT&amp;CK
            mapping.
          </p>
        </div>

        <button
          type="button"
          className="mitre-refresh-button"
          onClick={() =>
            loadMappings(true)
          }
          disabled={
            loading ||
            refreshing
          }
        >
          {refreshing
            ? "Refreshing feeds..."
            : "Refresh intelligence"}
        </button>
      </section>

      {error && (
        <section
          className="mitre-error"
          role="alert"
        >
          <div>
            <strong>
              MITRE data could not
              be loaded
            </strong>

            <p>{error}</p>
          </div>

          <button
            type="button"
            onClick={() =>
              loadMappings(false)
            }
          >
            Try again
          </button>
        </section>
      )}

      {successMessage && (
        <section
          className="mitre-error"
          role="status"
          style={{
            borderColor:
              "rgba(52, 211, 153, 0.25)",
            background:
              "rgba(52, 211, 153, 0.08)",
          }}
        >
          <div>
            <strong
              style={{
                color:
                  "#34d399",
              }}
            >
              Refresh completed
            </strong>

            <p>
              {successMessage}
            </p>
          </div>
        </section>
      )}

      <section className="mitre-kpi-grid">
        <article className="mitre-kpi-card">
          <span>
            Mapping coverage
          </span>

          <strong>
            {
              summary.mapping_coverage
            }
            %
          </strong>

          <small>
            Threat records mapped
          </small>
        </article>

        <article className="mitre-kpi-card">
          <span>
            Threat records
          </span>

          <strong>
            {
              summary.threat_records
            }
          </strong>

          <small>
            Latest intelligence
          </small>
        </article>

        <article className="mitre-kpi-card">
          <span>
            Techniques
          </span>

          <strong>
            {
              summary.technique_count
            }
          </strong>

          <small>
            Unique ATT&amp;CK IDs
          </small>
        </article>

        <article className="mitre-kpi-card">
          <span>
            Tactics
          </span>

          <strong>
            {
              summary.tactic_count
            }
          </strong>

          <small>
            Adversary objectives
          </small>
        </article>

        <article className="mitre-kpi-card mitre-kpi-critical">
          <span>
            Critical mappings
          </span>

          <strong>
            {
              summary.critical_mappings
            }
          </strong>

          <small>
            Immediate review
          </small>
        </article>
      </section>

      <section className="mitre-toolbar">
        <label className="mitre-search">
          <span>
            Search technique or IOC
          </span>

          <input
            type="search"
            value={searchTerm}
            onChange={(event) =>
              setSearchTerm(
                event.target.value,
              )
            }
            placeholder="Search T1566, phishing, URL or source"
          />
        </label>

        <label>
          <span>Tactic</span>

          <select
            value={tacticFilter}
            onChange={(event) =>
              setTacticFilter(
                event.target.value,
              )
            }
          >
            <option value="All">
              All tactics
            </option>

            {tactics.map(
              (tactic) => (
                <option
                  key={tactic}
                  value={tactic}
                >
                  {tactic}
                </option>
              ),
            )}
          </select>
        </label>

        <label>
          <span>Severity</span>

          <select
            value={
              severityFilter
            }
            onChange={(event) =>
              setSeverityFilter(
                event.target.value,
              )
            }
          >
            <option value="All">
              All severities
            </option>

            <option value="Critical">
              Critical
            </option>

            <option value="High">
              High
            </option>

            <option value="Medium">
              Medium
            </option>

            <option value="Low">
              Low
            </option>
          </select>
        </label>

        <button
          type="button"
          className="mitre-clear-button"
          onClick={clearFilters}
        >
          Clear filters
        </button>
      </section>

      {loading ? (
        <section className="mitre-loading">
          <div className="mitre-spinner" />

          <h2>
            Loading MITRE mappings
          </h2>

          <p>
            Reading the latest
            aggregated ATT&amp;CK
            techniques.
          </p>
        </section>
      ) : (
        <section className="mitre-workspace">
          <div className="mitre-matrix-panel">
            <div className="mitre-panel-heading">
              <div>
                <span>
                  ATT&amp;CK mapping
                </span>

                <h2>
                  Technique explorer
                </h2>
              </div>

              <strong>
                {
                  filteredTechniques.length
                }{" "}
                techniques
              </strong>
            </div>

            {groupedTechniques.length ===
            0 ? (
              <div className="mitre-empty">
                <h3>
                  No techniques found
                </h3>

                <p>
                  Adjust your search or
                  filters.
                </p>

                <button
                  type="button"
                  onClick={
                    clearFilters
                  }
                >
                  Reset filters
                </button>
              </div>
            ) : (
              <div className="mitre-groups">
                {groupedTechniques.map(
                  (group) => (
                    <section
                      className="mitre-tactic-group"
                      key={
                        group.tactic
                      }
                    >
                      <header>
                        <div>
                          <span>
                            ATT&amp;CK
                            tactic
                          </span>

                          <h3>
                            {
                              group.tactic
                            }
                          </h3>
                        </div>

                        <strong>
                          {group.records.reduce(
                            (
                              total,
                              item,
                            ) =>
                              total +
                              item.count,
                            0,
                          )}
                        </strong>
                      </header>

                      <div className="mitre-technique-list">
                        {group.records.map(
                          (item) => {
                            const selected =
                              selectedTechnique
                                ?.id ===
                              item.id;

                            return (
                              <button
                                type="button"
                                className={`mitre-technique-card ${
                                  selected
                                    ? "is-selected"
                                    : ""
                                }`}
                                key={
                                  item.id
                                }
                                onClick={() =>
                                  setSelectedTechnique(
                                    item,
                                  )
                                }
                              >
                                <div className="mitre-technique-card-top">
                                  <span className="mitre-technique-id">
                                    {
                                      item.technique
                                    }
                                  </span>

                                  <span
                                    className={`mitre-severity ${getSeverityClass(
                                      item.severity,
                                    )}`}
                                  >
                                    {
                                      item.severity
                                    }
                                  </span>
                                </div>

                                <strong>
                                  {
                                    item.name
                                  }
                                </strong>

                                <p>
                                  {
                                    item.count
                                  }{" "}
                                  related
                                  indicator
                                  {item.count ===
                                  1
                                    ? ""
                                    : "s"}
                                </p>

                                <small>
                                  Average
                                  confidence:{" "}
                                  {formatConfidence(
                                    item.average_confidence,
                                  )}
                                </small>
                              </button>
                            );
                          },
                        )}
                      </div>
                    </section>
                  ),
                )}
              </div>
            )}
          </div>

          <aside className="mitre-details-panel">
            <div className="mitre-panel-heading">
              <div>
                <span>
                  Investigation
                </span>

                <h2>
                  Technique details
                </h2>
              </div>
            </div>

            {selectedTechnique ? (
              <div className="mitre-details-content">
                <div className="mitre-details-title">
                  <span className="mitre-technique-id">
                    {
                      selectedTechnique.technique
                    }
                  </span>

                  <span
                    className={`mitre-severity ${getSeverityClass(
                      selectedTechnique.severity,
                    )}`}
                  >
                    {
                      selectedTechnique.severity
                    }
                  </span>

                  <h3>
                    {
                      selectedTechnique.name
                    }
                  </h3>

                  <p>
                    {
                      selectedTechnique.tactic
                    }
                  </p>
                </div>

                <dl className="mitre-details-list">
                  <div>
                    <dt>
                      Occurrences
                    </dt>

                    <dd>
                      {
                        selectedTechnique.count
                      }
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Average confidence
                    </dt>

                    <dd>
                      {formatConfidence(
                        selectedTechnique.average_confidence,
                      )}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Highest confidence
                    </dt>

                    <dd>
                      {formatConfidence(
                        selectedTechnique.highest_confidence,
                      )}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Last observed
                    </dt>

                    <dd>
                      {formatDate(
                        selectedTechnique.last_seen,
                      )}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Intelligence sources
                    </dt>

                    <dd>
                      {selectedTechnique
                        .sources
                        .length >
                      0
                        ? selectedTechnique.sources.join(
                            ", ",
                          )
                        : "Unknown"}
                    </dd>
                  </div>
                </dl>

                <section className="mitre-response-box">
                  <span>
                    Related indicators
                  </span>

                  <h4>
                    Select an IOC
                  </h4>

                  <p>
                    {
                      selectedTechnique
                        .indicators
                        .length
                    }{" "}
                    threat intelligence
                    records are grouped
                    under this technique.
                  </p>
                </section>

                <div
                  style={{
                    display:
                      "flex",
                    flexDirection:
                      "column",
                    gap: "10px",
                    marginTop:
                      "16px",
                  }}
                >
                  {selectedTechnique
                    .indicators
                    .length === 0 ? (
                    <div className="mitre-empty mitre-details-empty">
                      <h3>
                        No related
                        indicators
                      </h3>

                      <p>
                        This technique
                        does not contain
                        IOC details.
                      </p>
                    </div>
                  ) : (
                    selectedTechnique.indicators.map(
                      (
                        indicator,
                      ) => {
                        const active =
                          selectedIndicator
                            ?.id ===
                          indicator.id;

                        return (
                          <button
                            type="button"
                            key={
                              indicator.id
                            }
                            className={`mitre-technique-card ${
                              active
                                ? "is-selected"
                                : ""
                            }`}
                            onClick={() =>
                              setSelectedIndicator(
                                indicator,
                              )
                            }
                            style={{
                              width:
                                "100%",
                              textAlign:
                                "left",
                            }}
                          >
                            <strong>
                              {
                                indicator.url
                              }
                            </strong>

                            <p>
                              Source:{" "}
                              {
                                indicator.source
                              }
                            </p>

                            <small>
                              Confidence:{" "}
                              {formatConfidence(
                                indicator.confidence,
                              )}
                            </small>
                          </button>
                        );
                      },
                    )
                  )}
                </div>

                {selectedIndicator && (
                  <dl className="mitre-details-list">
                    <div>
                      <dt>
                        Selected
                        indicator
                      </dt>

                      <dd className="mitre-break-text">
                        {
                          selectedIndicator.url
                        }
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Threat type
                      </dt>

                      <dd>
                        {
                          selectedIndicator.threat_type
                        }
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Source
                      </dt>

                      <dd>
                        {
                          selectedIndicator.source
                        }
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Confidence
                      </dt>

                      <dd>
                        {formatConfidence(
                          selectedIndicator.confidence,
                        )}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Last observed
                      </dt>

                      <dd>
                        {formatDate(
                          selectedIndicator.last_seen,
                        )}
                      </dd>
                    </div>
                  </dl>
                )}
              </div>
            ) : (
              <div className="mitre-empty mitre-details-empty">
                <h3>
                  Select a technique
                </h3>

                <p>
                  Choose an ATT&amp;CK
                  technique to inspect
                  its related indicators.
                </p>
              </div>
            )}
          </aside>
        </section>
      )}
    </main>
  );
}