import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bug,
  CheckCircle2,
  Clock3,
  Database,
  FileSearch,
  Fingerprint,
  Gauge,
  Globe2,
  MailSearch,
  Network,
  Radar,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Target,
  Workflow,
} from "lucide-react";

import { useAuth } from "../context/AuthContext";

import LoadingOverlay from "../components/LoadingOverlay";

import {
  mitre,
  orchestrator,
  reports,
  scan,
  threats,
} from "../services/api";

import useWebSocket from "../hooks/useWebSocket";

import "./Dashboard.css";

const SEVERITY_COLOURS = {
  Critical: "#f87171",
  High: "#fb923c",
  Medium: "#fbbf24",
  Low: "#34d399",
  Unknown: "#94a3b8",
};

const SOURCE_COLOURS = [
  "#38bdf8",
  "#818cf8",
  "#34d399",
  "#fbbf24",
  "#f87171",
  "#fb923c",
];

const EMPTY_MITRE_SUMMARY = {
  mapping_coverage: 0,
  threat_records: 0,
  technique_count: 0,
  tactic_count: 0,
  critical_mappings: 0,
};

function normaliseConfidence(value) {
  const numericValue = Number(value);

  if (!Number.isFinite(numericValue)) {
    return 0;
  }

  if (numericValue > 1) {
    return Math.min(
      100,
      Math.max(0, numericValue),
    );
  }

  return Math.min(
    100,
    Math.max(0, numericValue * 100),
  );
}

function normaliseThreatScore(value) {
  const numericValue = Number(value);

  if (!Number.isFinite(numericValue)) {
    return 0;
  }

  if (numericValue > 1) {
    return Math.min(
      1,
      Math.max(0, numericValue / 100),
    );
  }

  return Math.min(
    1,
    Math.max(0, numericValue),
  );
}

function threatSeverity(entry) {
  const confidence =
    normaliseConfidence(
      entry?.confidence,
    );

  if (confidence >= 85) {
    return "Critical";
  }

  if (confidence >= 70) {
    return "High";
  }

  if (confidence >= 45) {
    return "Medium";
  }

  return "Low";
}

function scoreColour(score) {
  const normalised =
    normaliseThreatScore(score);

  if (normalised > 0.6) {
    return "#f87171";
  }

  if (normalised > 0.3) {
    return "#fbbf24";
  }

  return "#34d399";
}

function scoreLabel(score) {
  const normalised =
    normaliseThreatScore(score);

  if (normalised > 0.6) {
    return "High Risk";
  }

  if (normalised > 0.3) {
    return "Suspicious";
  }

  return "Safe";
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
    return "Not available";
  }

  return date.toLocaleString();
}

function formatShortDate(value) {
  const date = new Date(value);

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return "Unknown";
  }

  return date.toLocaleDateString(
    undefined,
    {
      month: "short",
      day: "numeric",
    },
  );
}

function sourceLabel(value) {
  return String(value || "Unknown")
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) =>
      letter.toUpperCase(),
    );
}

function getIncidentActions(
  incident,
) {
  return Array.isArray(
    incident?.actions,
  )
    ? incident.actions
    : [];
}

function getIncidentStatus(
  incident,
) {
  const actions =
    getIncidentActions(incident);

  if (
    actions.some(
      (action) =>
        action?.status ===
        "PENDING_APPROVAL",
    )
  ) {
    return "Pending";
  }

  if (
    actions.some(
      (action) =>
        action?.status ===
        "EXECUTED",
    )
  ) {
    return "Executed";
  }

  if (
    actions.some(
      (action) =>
        action?.status ===
        "APPROVED",
    )
  ) {
    return "Approved";
  }

  if (
    actions.some(
      (action) =>
        action?.status ===
        "BLOCKED",
    )
  ) {
    return "Blocked";
  }

  return "Manual Review";
}

function statusClass(status) {
  return String(status || "")
    .toLowerCase()
    .replace(/\s+/g, "-");
}

function buildTrendData(history) {
  const days = [];
  const today = new Date();

  today.setHours(
    0,
    0,
    0,
    0,
  );

  for (
    let index = 13;
    index >= 0;
    index -= 1
  ) {
    const day =
      new Date(today);

    day.setDate(
      day.getDate() - index,
    );

    days.push({
      key:
        day.toDateString(),
      name:
        formatShortDate(day),
      scores: [],
    });
  }

  const dayMap =
    new Map(
      days.map((day) => [
        day.key,
        day,
      ]),
    );

  history.forEach((entry) => {
    const createdAt =
      new Date(
        entry?.created_at,
      );

    if (
      Number.isNaN(
        createdAt.getTime(),
      )
    ) {
      return;
    }

    createdAt.setHours(
      0,
      0,
      0,
      0,
    );

    const bucket =
      dayMap.get(
        createdAt.toDateString(),
      );

    if (!bucket) {
      return;
    }

    bucket.scores.push(
      normaliseThreatScore(
        entry?.threat_score,
      ),
    );
  });

  return days.map((day) => ({
    name: day.name,

    averageThreat:
      day.scores.length > 0
        ? Math.round(
            (day.scores.reduce(
              (
                total,
                score,
              ) =>
                total + score,
              0,
            ) /
              day.scores.length) *
              100,
          )
        : 0,

    scans:
      day.scores.length,
  }));
}

function computeSecurityScore(
  history,
  incidents,
) {
  if (
    history.length === 0 &&
    incidents.length === 0
  ) {
    return 100;
  }

  const maliciousCount =
    history.filter(
      (entry) =>
        entry?.is_malicious ||
        normaliseThreatScore(
          entry?.threat_score,
        ) > 0.6,
    ).length;

  const maliciousRate =
    history.length > 0
      ? maliciousCount /
        history.length
      : 0;

  const pendingIncidents =
    incidents.filter(
      (incident) =>
        getIncidentStatus(
          incident,
        ) === "Pending",
    ).length;

  let score = 100;

  score -= Math.round(
    maliciousRate * 55,
  );

  score -= Math.min(
    35,
    pendingIncidents * 7,
  );

  return Math.max(
    0,
    Math.min(100, score),
  );
}

function getDomain(entry) {
  if (entry?.domain) {
    return entry.domain;
  }

  try {
    const url =
      new URL(entry?.url);

    return url.hostname;
  } catch {
    return (
      entry?.url ||
      "Unknown"
    );
  }
}

function CustomTooltip({
  active,
  payload,
  label,
}) {
  if (
    !active ||
    !payload ||
    payload.length === 0
  ) {
    return null;
  }

  return (
    <div className="dash-chart-tooltip">
      {label && (
        <strong>{label}</strong>
      )}

      {payload.map((entry) => (
        <div
          key={
            entry.dataKey ||
            entry.name
          }
        >
          <span>
            {entry.name}
          </span>

          <b>
            {entry.value}
            {entry.dataKey ===
            "averageThreat"
              ? "%"
              : ""}
          </b>
        </div>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const { user } = useAuth();

  const {
    connected,
    alerts,
  } = useWebSocket();

  const [
    history,
    setHistory,
  ] = useState([]);

  const [
    threatList,
    setThreatList,
  ] = useState([]);

  const [
    incidents,
    setIncidents,
  ] = useState([]);

  const [
    mitreTechniques,
    setMitreTechniques,
  ] = useState([]);

  const [
    mitreSummary,
    setMitreSummary,
  ] = useState(
    EMPTY_MITRE_SUMMARY,
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
    url,
    setUrl,
  ] = useState("");

  const [
    result,
    setResult,
  ] = useState(null);

  const [
    scanning,
    setScanning,
  ] = useState(false);

  const [
    downloading,
    setDownloading,
  ] = useState(false);

  const [
    error,
    setError,
  ] = useState("");

  const loadDashboard =
    useCallback(async () => {
      setError("");

      const results =
        await Promise.allSettled([
          scan.history(),
          threats.recent(),
          orchestrator.list(),
          mitre.getMappings(),
        ]);

      const [
        historyResult,
        threatsResult,
        incidentsResult,
        mitreResult,
      ] = results;

      if (
        historyResult.status ===
        "fulfilled"
      ) {
        const payload =
          historyResult.value?.data;

        setHistory(
          Array.isArray(payload)
            ? payload
            : [],
        );
      }

      if (
        threatsResult.status ===
        "fulfilled"
      ) {
        const payload =
          threatsResult.value?.data;

        setThreatList(
          Array.isArray(payload)
            ? payload
            : Array.isArray(
                  payload?.entries,
                )
              ? payload.entries
              : [],
        );
      }

      if (
        incidentsResult.status ===
        "fulfilled"
      ) {
        const payload =
          incidentsResult.value
            ?.data;

        setIncidents(
          Array.isArray(payload)
            ? payload
            : Array.isArray(
                  payload?.incidents,
                )
              ? payload.incidents
              : [],
        );
      }

      if (
        mitreResult.status ===
        "fulfilled"
      ) {
        const payload =
          mitreResult.value?.data ||
          {};

        setMitreTechniques(
          Array.isArray(
            payload.techniques,
          )
            ? payload.techniques
            : [],
        );

        setMitreSummary({
          ...EMPTY_MITRE_SUMMARY,
          ...(payload.summary ||
            {}),
        });
      }

      const failed =
        results.filter(
          (item) =>
            item.status ===
            "rejected",
        );

      if (failed.length > 0) {
        setError(
          `${failed.length} dashboard data source${
            failed.length === 1
              ? ""
              : "s"
          } could not be loaded.`,
        );
      }

      setLoading(false);
    }, []);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  const refreshDashboard =
    useCallback(async () => {
      setRefreshing(true);
      setError("");

      try {
        await threats.fetchFeeds();
      } catch (requestError) {
        console.error(
          "[Dashboard feed refresh]",
          requestError,
        );
      }

      await loadDashboard();

      setRefreshing(false);
    }, [loadDashboard]);

  const doScan = async () => {
    const query =
      url.trim();

    if (!query) {
      return;
    }

    setScanning(true);
    setResult(null);
    setError("");

    try {
      const response =
        await scan.url(query);

      setResult(
        response?.data || null,
      );

      const historyResponse =
        await scan.history();

      setHistory(
        Array.isArray(
          historyResponse?.data,
        )
          ? historyResponse.data
          : [],
      );
    } catch (
      requestError
    ) {
      console.error(
        "[Dashboard URL scan]",
        requestError,
      );

      setResult({
        error: true,
        message:
          requestError?.response?.data
            ?.error ||
          "URL scan failed.",
      });
    } finally {
      setScanning(false);
    }
  };

  const downloadPdf =
    async () => {
      if (
        !result ||
        result.error ||
        downloading
      ) {
        return;
      }

      setDownloading(true);

      try {
        await reports.generate(
          result,
        );
      } catch (
        requestError
      ) {
        console.error(
          "[Dashboard PDF]",
          requestError,
        );

        setError(
          "PDF generation failed.",
        );
      } finally {
        setDownloading(false);
      }
    };

  const trendData =
    useMemo(
      () =>
        buildTrendData(
          history,
        ),
      [history],
    );

  const averageThreatScore =
    useMemo(() => {
      if (
        history.length === 0
      ) {
        return 0;
      }

      const total =
        history.reduce(
          (
            accumulator,
            entry,
          ) =>
            accumulator +
            normaliseThreatScore(
              entry?.threat_score,
            ),
          0,
        );

      return Math.round(
        (total /
          history.length) *
          100,
      );
    }, [history]);

  const maliciousScanCount =
    useMemo(
      () =>
        history.filter(
          (entry) =>
            entry?.is_malicious ||
            normaliseThreatScore(
              entry?.threat_score,
            ) > 0.6,
        ).length,
      [history],
    );

  const safeScanCount =
    useMemo(
      () =>
        history.filter(
          (entry) =>
            !entry?.is_malicious &&
            normaliseThreatScore(
              entry?.threat_score,
            ) <= 0.3,
        ).length,
      [history],
    );

  const suspiciousScanCount =
    useMemo(
      () =>
        history.filter(
          (entry) => {
            const score =
              normaliseThreatScore(
                entry?.threat_score,
              );

            return (
              score > 0.3 &&
              score <= 0.6
            );
          },
        ).length,
      [history],
    );

  const criticalThreatCount =
    useMemo(
      () =>
        threatList.filter(
          (entry) =>
            threatSeverity(
              entry,
            ) === "Critical",
        ).length,
      [threatList],
    );

  const activeIncidentCount =
    useMemo(
      () =>
        incidents.filter(
          (incident) =>
            getIncidentStatus(
              incident,
            ) === "Pending",
        ).length,
      [incidents],
    );

  const executedActionCount =
    useMemo(
      () =>
        incidents.reduce(
          (
            total,
            incident,
          ) =>
            total +
            getIncidentActions(
              incident,
            ).filter(
              (action) =>
                action?.status ===
                "EXECUTED",
            ).length,
          0,
        ),
      [incidents],
    );

  const securityScore =
    useMemo(
      () =>
        computeSecurityScore(
          history,
          incidents,
        ),
      [
        history,
        incidents,
      ],
    );

  const scanDistribution =
    useMemo(
      () => [
        {
          name: "Safe",
          value:
            safeScanCount,
          colour:
            "#34d399",
        },
        {
          name:
            "Suspicious",
          value:
            suspiciousScanCount,
          colour:
            "#fbbf24",
        },
        {
          name:
            "Malicious",
          value:
            maliciousScanCount,
          colour:
            "#f87171",
        },
      ],
      [
        safeScanCount,
        suspiciousScanCount,
        maliciousScanCount,
      ],
    );

  const severityDistribution =
    useMemo(() => {
      const counts = {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0,
      };

      threatList.forEach(
        (entry) => {
          const severity =
            threatSeverity(entry);

          counts[severity] += 1;
        },
      );

      return Object.entries(
        counts,
      ).map(
        ([
          name,
          value,
        ]) => ({
          name,
          value,
          colour:
            SEVERITY_COLOURS[
              name
            ],
        }),
      );
    }, [threatList]);

  const threatSourceData =
    useMemo(() => {
      const counts = {};

      threatList.forEach(
        (entry) => {
          const source =
            sourceLabel(
              entry?.source,
            );

          counts[source] =
            (counts[source] ||
              0) + 1;
        },
      );

      return Object.entries(
        counts,
      )
        .map(
          ([
            name,
            value,
          ]) => ({
            name,
            value,
          }),
        )
        .sort(
          (
            first,
            second,
          ) =>
            second.value -
            first.value,
        )
        .slice(0, 6);
    }, [threatList]);

  const tacticData =
    useMemo(() => {
      return mitreTechniques
        .filter(
          (item) =>
            item?.tactic &&
            item.tactic !==
              "Unknown",
        )
        .map((item) => ({
          name:
            item.tactic,
          count:
            Number(
              item?.count,
            ) || 0,
        }))
        .sort(
          (
            first,
            second,
          ) =>
            second.count -
            first.count,
        )
        .slice(0, 7);
    }, [mitreTechniques]);

  const topTechnique =
    useMemo(() => {
      if (
        mitreTechniques.length ===
        0
      ) {
        return null;
      }

      return [
        ...mitreTechniques,
      ].sort(
        (
          first,
          second,
        ) =>
          (Number(
            second?.count,
          ) || 0) -
          (Number(
            first?.count,
          ) || 0),
      )[0];
    }, [mitreTechniques]);

  const recentThreats =
    useMemo(
      () =>
        threatList
          .slice()
          .sort(
            (
              first,
              second,
            ) =>
              new Date(
                second?.last_seen ||
                  second?.updated_at ||
                  0,
              ).getTime() -
              new Date(
                first?.last_seen ||
                  first?.updated_at ||
                  0,
              ).getTime(),
          )
          .slice(0, 7),
      [threatList],
    );

  const recentIncidents =
    useMemo(
      () =>
        incidents
          .slice()
          .sort(
            (
              first,
              second,
            ) =>
              new Date(
                second?.created_at ||
                  second?.timestamp ||
                  0,
              ).getTime() -
              new Date(
                first?.created_at ||
                  first?.timestamp ||
                  0,
              ).getTime(),
          )
          .slice(0, 6),
      [incidents],
    );

  const moduleCards =
    useMemo(
      () => [
        {
          name:
            "Email Analyzer",
          icon:
            MailSearch,
          status:
            "Operational",
          events:
            history.length,
          detail:
            "Header and phishing analysis",
        },
        {
          name:
            "Reconnaissance",
          icon: Globe2,
          status:
            "Operational",
          events:
            history.length,
          detail:
            "DNS, WHOIS and port intelligence",
        },
        {
          name:
            "Threat Intelligence",
          icon: Radar,
          status:
            threatList.length >
            0
              ? "Operational"
              : "Waiting",
          events:
            threatList.length,
          detail:
            "External IOC feeds",
        },
        {
          name:
            "YARA Scanner",
          icon:
            FileSearch,
          status:
            "Operational",
          events: 7,
          detail:
            "Rule-based detection",
        },
        {
          name:
            "Breach Checker",
          icon:
            Fingerprint,
          status:
            "Operational",
          events: 0,
          detail:
            "HIBP k-anonymity checks",
        },
        {
          name:
            "GoPhish",
          icon: Bug,
          status:
            "Operational",
          events: 0,
          detail:
            "Phishing simulation",
        },
        {
          name:
            "MITRE ATT&CK",
          icon: Network,
          status:
            mitreSummary.technique_count >
            0
              ? "Operational"
              : "Waiting",
          events:
            mitreSummary.technique_count,
          detail:
            `${mitreSummary.mapping_coverage}% mapping coverage`,
        },
        {
          name:
            "Response Engine",
          icon:
            Workflow,
          status:
            activeIncidentCount >
            0
              ? "Attention"
              : "Operational",
          events:
            incidents.length,
          detail:
            `${activeIncidentCount} pending approvals`,
        },
      ],
      [
        history.length,
        threatList.length,
        mitreSummary,
        activeIncidentCount,
        incidents.length,
      ],
    );

  const kpiCards = [
    {
      label:
        "Threat Records",
      value:
        threatList.length,
      description:
        "Indicators from connected feeds",
      icon: Database,
      colour:
        "#38bdf8",
    },
    {
      label:
        "Critical Threats",
      value:
        criticalThreatCount,
      description:
        "Highest-priority IOC mappings",
      icon:
        ShieldAlert,
      colour:
        "#f87171",
    },
    {
      label:
        "MITRE Coverage",
      value:
        `${Number(
          mitreSummary.mapping_coverage,
        ) || 0}%`,
      description:
        `${Number(
          mitreSummary.technique_count,
        ) || 0} mapped techniques`,
      icon: Target,
      colour:
        "#818cf8",
    },
    {
      label:
        "Active Incidents",
      value:
        activeIncidentCount,
      description:
        `${incidents.length} total incidents`,
      icon:
        AlertTriangle,
      colour:
        activeIncidentCount >
        0
          ? "#fb923c"
          : "#34d399",
    },
    {
      label:
        "Response Actions",
      value:
        executedActionCount,
      description:
        "Executed containment actions",
      icon: Workflow,
      colour:
        "#fbbf24",
    },
    {
      label:
        "Platform Health",
      value:
        `${securityScore}%`,
      description:
        connected
          ? "Live services connected"
          : "Live feed reconnecting",
      icon:
        ShieldCheck,
      colour:
        securityScore >= 80
          ? "#34d399"
          : securityScore >=
              55
            ? "#fbbf24"
            : "#f87171",
    },
  ];

  if (loading) {
    return (
      <LoadingOverlay
        text="Loading SOC Dashboard..."
      />
    );
  }

  return (
  <main className="dash-page">
    <section className="dash-dashboard-actions">
      <div>
        <span className="dash-dashboard-actions-label">
          Command centre overview
        </span>

        <p>
          Live threat intelligence, MITRE coverage, detection health and
          response activity.
        </p>
      </div>

      <button
        type="button"
        className="dash-global-refresh"
        onClick={refreshDashboard}
        disabled={refreshing}
      >
        <RefreshCw
          size={16}
          className={
            refreshing
              ? "dash-spin"
              : ""
          }
        />

        {refreshing
          ? "Refreshing intelligence..."
          : "Refresh intelligence"}
      </button>
    </section>

    <section className="dash-status-strip">
        <div>
          <span
            className={`dash-status-dot ${
              connected
                ? "is-online"
                : "is-warning"
            }`}
          />

          <div>
            <small>
              Platform status
            </small>

            <strong>
              {connected
                ? "Operational"
                : "Reconnecting"}
            </strong>
          </div>
        </div>

        <div>
          <Gauge size={18} />

          <div>
            <small>
              Threat level
            </small>

            <strong className="dash-threat-level">
              {criticalThreatCount >
              0
                ? "Elevated"
                : "Normal"}
            </strong>
          </div>
        </div>

        <div>
          <Activity size={18} />

          <div>
            <small>
              Detection engine
            </small>

            <strong>
              {securityScore}%
              healthy
            </strong>
          </div>
        </div>

        <div>
          <Clock3 size={18} />

          <div>
            <small>
              Last update
            </small>

            <strong>
              {new Date().toLocaleTimeString(
                [],
                {
                  hour:
                    "2-digit",
                  minute:
                    "2-digit",
                },
              )}
            </strong>
          </div>
        </div>
      </section>

      {error && (
        <section className="dash-error-banner">
          <AlertTriangle
            size={17}
          />

          <span>{error}</span>
        </section>
      )}

      {alerts.length > 0 && (
        <section className="dash-live-alerts">
          {alerts
            .slice(0, 3)
            .map(
              (
                alert,
                index,
              ) => (
                <article
                  key={`${alert.type}-${index}`}
                >
                  <span className="dash-live-alert-icon">
                    {alert.type ===
                    "threat_alert" ? (
                      <ShieldAlert
                        size={16}
                      />
                    ) : (
                      <CheckCircle2
                        size={16}
                      />
                    )}
                  </span>

                  <div>
                    <strong>
                      {alert.type ===
                      "threat_alert"
                        ? "Threat alert"
                        : "Scan completed"}
                    </strong>

                    <p>
                      {alert.data
                        ?.url ||
                        alert.data
                          ?.domain ||
                        "Security event received"}
                    </p>
                  </div>
                </article>
              ),
            )}
        </section>
      )}

      <section className="dash-kpi-grid">
        {kpiCards.map(
          (card) => {
            const Icon =
              card.icon;

            return (
              <article
                className="dash-kpi-card"
                key={card.label}
              >
                <div
                  className="dash-kpi-icon"
                  style={{
                    color:
                      card.colour,
                    background:
                      `${card.colour}16`,
                  }}
                >
                  <Icon size={20} />
                </div>

                <span>
                  {card.label}
                </span>

                <strong
                  style={{
                    color:
                      card.colour,
                  }}
                >
                  {loading
                    ? "—"
                    : card.value}
                </strong>

                <small>
                  {
                    card.description
                  }
                </small>
              </article>
            );
          },
        )}
      </section>

      <section className="dash-overview-grid">
        <article className="dash-panel dash-panel-large">
          <div className="dash-panel-header">
            <div>
              <span className="dash-section-label">
                Threat activity
              </span>

              <h2>
                Threat Trend
              </h2>

              <p>
                Average URL risk score
                and scan activity over
                the last 14 days.
              </p>
            </div>

            <span className="dash-panel-pill">
              {history.length} scans
            </span>
          </div>

          <div className="dash-chart-area">
            <ResponsiveContainer
              width="100%"
              height={280}
            >
              <AreaChart
                data={trendData}
              >
                <defs>
                  <linearGradient
                    id="dashThreatGradient"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop
                      offset="0%"
                      stopColor="#38bdf8"
                      stopOpacity={
                        0.38
                      }
                    />

                    <stop
                      offset="100%"
                      stopColor="#38bdf8"
                      stopOpacity={0}
                    />
                  </linearGradient>
                </defs>

                <CartesianGrid
                  strokeDasharray="3 3"
                  vertical={false}
                  stroke="rgba(148,163,184,0.08)"
                />

                <XAxis
                  dataKey="name"
                  tick={{
                    fill:
                      "#64748b",
                    fontSize: 11,
                  }}
                  axisLine={false}
                  tickLine={false}
                />

                <YAxis
                  domain={[0, 100]}
                  tick={{
                    fill:
                      "#64748b",
                    fontSize: 11,
                  }}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(
                    value,
                  ) =>
                    `${value}%`
                  }
                />

                <Tooltip
                  content={
                    <CustomTooltip />
                  }
                />

                <Area
                  type="monotone"
                  dataKey="averageThreat"
                  name="Average threat"
                  stroke="#38bdf8"
                  strokeWidth={2.4}
                  fill="url(#dashThreatGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </article>

        <article className="dash-panel">
          <div className="dash-panel-header">
            <div>
              <span className="dash-section-label">
                Detection profile
              </span>

              <h2>
                Severity Distribution
              </h2>

              <p>
                Threat records grouped
                by confidence.
              </p>
            </div>
          </div>

          <div className="dash-donut-wrap">
            <ResponsiveContainer
              width="100%"
              height={220}
            >
              <PieChart>
                <Pie
                  data={
                    severityDistribution
                  }
                  cx="50%"
                  cy="50%"
                  innerRadius={58}
                  outerRadius={86}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {severityDistribution.map(
                    (entry) => (
                      <Cell
                        key={
                          entry.name
                        }
                        fill={
                          entry.colour
                        }
                        stroke="transparent"
                      />
                    ),
                  )}
                </Pie>

                <Tooltip
                  content={
                    <CustomTooltip />
                  }
                />
              </PieChart>
            </ResponsiveContainer>

            <div className="dash-donut-centre">
              <strong>
                {threatList.length}
              </strong>

              <span>
                Threats
              </span>
            </div>
          </div>

          <div className="dash-chart-legend">
            {severityDistribution.map(
              (entry) => (
                <div
                  key={entry.name}
                >
                  <span
                    style={{
                      background:
                        entry.colour,
                    }}
                  />

                  <small>
                    {entry.name}
                  </small>

                  <strong>
                    {entry.value}
                  </strong>
                </div>
              ),
            )}
          </div>
        </article>
      </section>

      <section className="dash-overview-grid">
        <article className="dash-panel">
          <div className="dash-panel-header">
            <div>
              <span className="dash-section-label">
                Intelligence sources
              </span>

              <h2>
                Threat Sources
              </h2>

              <p>
                IOC volume by external
                provider.
              </p>
            </div>
          </div>

          <ResponsiveContainer
            width="100%"
            height={280}
          >
            <BarChart
              data={threatSourceData}
              layout="vertical"
              margin={{
                left: 18,
                right: 16,
              }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                horizontal={false}
                stroke="rgba(148,163,184,0.08)"
              />

              <XAxis
                type="number"
                axisLine={false}
                tickLine={false}
                tick={{
                  fill:
                    "#64748b",
                  fontSize: 11,
                }}
              />

              <YAxis
                type="category"
                dataKey="name"
                axisLine={false}
                tickLine={false}
                width={95}
                tick={{
                  fill:
                    "#94a3b8",
                  fontSize: 11,
                }}
              />

              <Tooltip
                content={
                  <CustomTooltip />
                }
              />

              <Bar
                dataKey="value"
                name="Indicators"
                radius={[
                  0,
                  7,
                  7,
                  0,
                ]}
              >
                {threatSourceData.map(
                  (
                    entry,
                    index,
                  ) => (
                    <Cell
                      key={
                        entry.name
                      }
                      fill={
                        SOURCE_COLOURS[
                          index %
                            SOURCE_COLOURS.length
                        ]
                      }
                    />
                  ),
                )}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </article>

        <article className="dash-panel">
          <div className="dash-panel-header">
            <div>
              <span className="dash-section-label">
                MITRE ATT&amp;CK
              </span>

              <h2>
                Tactic Coverage
              </h2>

              <p>
                Mapped records by
                adversary objective.
              </p>
            </div>

            <span className="dash-panel-pill">
              {
                mitreSummary.mapping_coverage
              }
              %
            </span>
          </div>

          {tacticData.length >
          0 ? (
            <ResponsiveContainer
              width="100%"
              height={280}
            >
              <BarChart
                data={tacticData}
                margin={{
                  top: 10,
                  left: 0,
                  right: 10,
                }}
              >
                <CartesianGrid
                  strokeDasharray="3 3"
                  vertical={false}
                  stroke="rgba(148,163,184,0.08)"
                />

                <XAxis
                  dataKey="name"
                  interval={0}
                  angle={-24}
                  textAnchor="end"
                  height={75}
                  axisLine={false}
                  tickLine={false}
                  tick={{
                    fill:
                      "#64748b",
                    fontSize: 10,
                  }}
                />

                <YAxis
                  axisLine={false}
                  tickLine={false}
                  tick={{
                    fill:
                      "#64748b",
                    fontSize: 11,
                  }}
                />

                <Tooltip
                  content={
                    <CustomTooltip />
                  }
                />

                <Bar
                  dataKey="count"
                  name="Mappings"
                  fill="#818cf8"
                  radius={[
                    7,
                    7,
                    0,
                    0,
                  ]}
                />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="dash-chart-empty">
              <Target
                size={28}
              />

              <strong>
                No MITRE data
              </strong>

              <span>
                Refresh intelligence to
                load ATT&amp;CK mappings.
              </span>
            </div>
          )}
        </article>
      </section>

      <section className="dash-data-grid">
        <article className="dash-panel dash-table-card">
          <div className="dash-panel-header">
            <div>
              <span className="dash-section-label">
                Threat intelligence
              </span>

              <h2>
                Recent Threats
              </h2>

              <p>
                Latest indicators
                requiring analyst
                visibility.
              </p>
            </div>

            <span className="dash-panel-pill">
              {
                recentThreats.length
              }{" "}
              records
            </span>
          </div>

          <div className="dash-table-scroll">
            <table className="dash-enterprise-table">
              <thead>
                <tr>
                  <th>
                    Severity
                  </th>
                  <th>
                    Indicator
                  </th>
                  <th>
                    Source
                  </th>
                  <th>
                    Confidence
                  </th>
                  <th>
                    Last Seen
                  </th>
                </tr>
              </thead>

              <tbody>
                {recentThreats.length >
                0 ? (
                  recentThreats.map(
                    (
                      threat,
                      index,
                    ) => {
                      const severity =
                        threatSeverity(
                          threat,
                        );

                      return (
                        <tr
                          key={
                            threat.id ||
                            `${threat.url}-${index}`
                          }
                        >
                          <td>
                            <span
                              className={`dash-severity dash-severity-${severity.toLowerCase()}`}
                            >
                              {
                                severity
                              }
                            </span>
                          </td>

                          <td>
                            <div className="dash-ioc-cell">
                              <strong>
                                {getDomain(
                                  threat,
                                )}
                              </strong>

                              <span>
                                {
                                  threat.url
                                }
                              </span>
                            </div>
                          </td>

                          <td>
                            {sourceLabel(
                              threat.source,
                            )}
                          </td>

                          <td>
                            <strong>
                              {Math.round(
                                normaliseConfidence(
                                  threat.confidence,
                                ),
                              )}
                              %
                            </strong>
                          </td>

                          <td>
                            {formatDate(
                              threat.last_seen ||
                                threat.updated_at,
                            )}
                          </td>
                        </tr>
                      );
                    },
                  )
                ) : (
                  <tr>
                    <td
                      colSpan="5"
                      className="dash-empty-row"
                    >
                      No threat
                      intelligence records
                      are currently
                      available.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </article>

        <article className="dash-panel">
          <div className="dash-panel-header">
            <div>
              <span className="dash-section-label">
                Orchestration
              </span>

              <h2>
                Response Queue
              </h2>

              <p>
                Recent incidents and
                action states.
              </p>
            </div>
          </div>

          <div className="dash-response-list">
            {recentIncidents.length >
            0 ? (
              recentIncidents.map(
                (
                  incident,
                  index,
                ) => {
                  const status =
                    getIncidentStatus(
                      incident,
                    );

                  return (
                    <article
                      key={
                        incident.id ||
                        index
                      }
                    >
                      <div className="dash-response-icon">
                        <Workflow
                          size={17}
                        />
                      </div>

                      <div className="dash-response-copy">
                        <strong>
                          {incident.title ||
                            incident.name ||
                            incident.incident_type ||
                            `Incident ${incident.id || index + 1}`}
                        </strong>

                        <span>
                          {incident.description ||
                            incident.source ||
                            "Automated security response"}
                        </span>
                      </div>

                      <span
                        className={`dash-response-status is-${statusClass(
                          status,
                        )}`}
                      >
                        {status}
                      </span>
                    </article>
                  );
                },
              )
            ) : (
              <div className="dash-chart-empty dash-small-empty">
                <CheckCircle2
                  size={26}
                />

                <strong>
                  Queue clear
                </strong>

                <span>
                  No incidents require
                  attention.
                </span>
              </div>
            )}
          </div>
        </article>
      </section>

      <section className="dash-data-grid">
        <article className="dash-panel">
          <div className="dash-panel-header">
            <div>
              <span className="dash-section-label">
                ATT&amp;CK posture
              </span>

              <h2>
                MITRE Summary
              </h2>

              <p>
                Current mapping coverage
                and dominant adversary
                behaviour.
              </p>
            </div>
          </div>

          <div className="dash-mitre-summary">
            <div className="dash-mitre-score">
              <div
                className="dash-mitre-ring"
                style={{
                  "--coverage":
                    `${Number(
                      mitreSummary.mapping_coverage,
                    ) || 0}%`,
                }}
              >
                <span>
                  {
                    mitreSummary.mapping_coverage
                  }
                  %
                </span>
              </div>

              <div>
                <strong>
                  Mapping coverage
                </strong>

                <p>
                  {
                    mitreSummary.threat_records
                  }{" "}
                  threat records mapped
                  across{" "}
                  {
                    mitreSummary.tactic_count
                  }{" "}
                  tactics.
                </p>
              </div>
            </div>

            <div className="dash-mitre-facts">
              <article>
                <span>
                  Top technique
                </span>

                <strong>
                  {topTechnique
                    ?.technique ||
                    "N/A"}
                </strong>

                <small>
                  {topTechnique?.name ||
                    "No mapped technique"}
                </small>
              </article>

              <article>
                <span>
                  Top tactic
                </span>

                <strong>
                  {topTechnique
                    ?.tactic ||
                    "N/A"}
                </strong>

                <small>
                  {Number(
                    topTechnique?.count,
                  ) || 0}{" "}
                  mapped indicators
                </small>
              </article>

              <article>
                <span>
                  Critical mappings
                </span>

                <strong>
                  {
                    mitreSummary.critical_mappings
                  }
                </strong>

                <small>
                  Immediate review
                </small>
              </article>
            </div>
          </div>
        </article>

        <article className="dash-panel">
          <div className="dash-panel-header">
            <div>
              <span className="dash-section-label">
                Detection stack
              </span>

              <h2>
                Detection Modules
              </h2>

              <p>
                Operational status of
                CyberShield services.
              </p>
            </div>
          </div>

          <div className="dash-module-grid">
            {moduleCards.map(
              (module) => {
                const Icon =
                  module.icon;

                return (
                  <article
                    key={
                      module.name
                    }
                  >
                    <div className="dash-module-icon">
                      <Icon
                        size={18}
                      />
                    </div>

                    <div className="dash-module-copy">
                      <strong>
                        {
                          module.name
                        }
                      </strong>

                      <span>
                        {
                          module.detail
                        }
                      </span>
                    </div>

                    <div className="dash-module-meta">
                      <span
                        className={`dash-module-status is-${module.status.toLowerCase()}`}
                      >
                        {
                          module.status
                        }
                      </span>

                      <small>
                        {
                          module.events
                        }{" "}
                        events
                      </small>
                    </div>
                  </article>
                );
              },
            )}
          </div>
        </article>
      </section>

      <section className="dash-panel dash-scanner-panel">
        <div className="dash-panel-header">
          <div>
            <span className="dash-section-label">
              On-demand analysis
            </span>

            <h2>
              URL Scanner
            </h2>

            <p>
              Analyse a URL using
              lexical, reputation, SSL,
              WHOIS and ML signals.
            </p>
          </div>
        </div>

        <div className="dash-scanner-row">
          <div className="dash-input-wrap">
            <Search size={18} />

            <input
              className="dash-input"
              value={url}
              onChange={(event) =>
                setUrl(
                  event.target.value,
                )
              }
              onKeyDown={(event) => {
                if (
                  event.key ===
                  "Enter"
                ) {
                  doScan();
                }
              }}
              placeholder="Enter URL to scan, for example https://suspicious-site.com"
            />
          </div>

          <button
            type="button"
            className="dash-scan-button"
            onClick={doScan}
            disabled={scanning}
          >
            {scanning
              ? "Scanning..."
              : "Scan URL"}
          </button>
        </div>

        {result?.error && (
          <div className="dash-scan-error">
            <AlertTriangle
              size={17}
            />

            {result.message ||
              "URL scan failed."}
          </div>
        )}

        {result &&
          !result.error && (
            <div className="dash-result-card">
              <div className="dash-result-header">
                <div>
                  <span className="dash-section-label">
                    Scan result
                  </span>

                  <h3>
                    {result.domain ||
                      getDomain(
                        result,
                      )}
                  </h3>

                  <p className="dash-result-url">
                    {result.url}
                  </p>
                </div>

                <div className="dash-result-score">
                  <strong
                    style={{
                      color:
                        scoreColour(
                          result.threat_score,
                        ),
                    }}
                  >
                    {Math.round(
                      normaliseThreatScore(
                        result.threat_score,
                      ) * 100,
                    )}
                    %
                  </strong>

                  <span
                    style={{
                      color:
                        scoreColour(
                          result.threat_score,
                        ),
                      background:
                        `${scoreColour(
                          result.threat_score,
                        )}18`,
                    }}
                  >
                    {scoreLabel(
                      result.threat_score,
                    )}
                  </span>
                </div>
              </div>

              <div className="dash-progress-track">
                <div
                  className="dash-progress-fill"
                  style={{
                    width:
                      `${normaliseThreatScore(
                        result.threat_score,
                      ) * 100}%`,

                    background:
                      scoreColour(
                        result.threat_score,
                      ),
                  }}
                />
              </div>

              <div className="dash-detail-grid">
                <article>
                  <span>
                    SSL certificate
                  </span>

                  <strong
                    style={{
                      color:
                        result.ssl_info
                          ?.has_ssl
                          ? "#34d399"
                          : "#f87171",
                    }}
                  >
                    {result.ssl_info
                      ?.has_ssl
                      ? "Valid"
                      : "Missing"}
                  </strong>
                </article>

                <article>
                  <span>
                    IP-based URL
                  </span>

                  <strong
                    style={{
                      color:
                        result.features
                          ?.has_ip_address
                          ? "#f87171"
                          : "#34d399",
                    }}
                  >
                    {result.features
                      ?.has_ip_address
                      ? "Detected"
                      : "No"}
                  </strong>
                </article>

                <article>
                  <span>
                    Domain age
                  </span>

                  <strong>
                    {result.whois_data
                      ?.domain_age_days
                      ? `${result.whois_data.domain_age_days} days`
                      : "N/A"}
                  </strong>
                </article>

                <article>
                  <span>
                    VirusTotal
                  </span>

                  <strong>
                    {result
                      .virustotal_result
                      ?.malicious_count ||
                      0}{" "}
                    flags
                  </strong>
                </article>
              </div>

              {result.ml_analysis
                ?.ml_available && (
                <div className="dash-ml-panel">
                  <div>
                    <span>
                      Random Forest
                    </span>

                    <strong>
                      {Math.round(
                        Number(
                          result
                            .ml_analysis
                            .rf_phishing_probability,
                        ) * 100,
                      )}
                      %
                    </strong>
                  </div>

                  <div>
                    <span>
                      Gradient Boost
                    </span>

                    <strong>
                      {Math.round(
                        Number(
                          result
                            .ml_analysis
                            .gb_phishing_probability,
                        ) * 100,
                      )}
                      %
                    </strong>
                  </div>

                  <div>
                    <span>
                      Ensemble
                    </span>

                    <strong>
                      {Math.round(
                        Number(
                          result
                            .ml_analysis
                            .ensemble_score,
                        ) * 100,
                      )}
                      %
                    </strong>
                  </div>

                  <div>
                    <span>
                      Verdict
                    </span>

                    <strong>
                      {result
                        .ml_analysis
                        .ensemble_prediction ||
                        "Unknown"}
                    </strong>
                  </div>
                </div>
              )}

              <button
                type="button"
                className="dash-download-button"
                onClick={
                  downloadPdf
                }
                disabled={
                  downloading
                }
              >
                {downloading
                  ? "Generating report..."
                  : "Download PDF report"}
              </button>
            </div>
          )}
      </section>

      <section className="dash-panel">
        <div className="dash-panel-header">
          <div>
            <span className="dash-section-label">
              Scan analytics
            </span>

            <h2>
              Recent Scan Scores
            </h2>

            <p>
              Threat scores from recent
              URL investigations.
            </p>
          </div>

          <span className="dash-panel-pill">
            {history.length} scans
          </span>
        </div>

        <ResponsiveContainer
          width="100%"
          height={280}
        >
          <BarChart
            data={history
              .slice(0, 10)
              .map((entry) => ({
                name:
                  getDomain(
                    entry,
                  ).slice(0, 18),

                score:
                  Math.round(
                    normaliseThreatScore(
                      entry?.threat_score,
                    ) * 100,
                  ),

                colour:
                  scoreColour(
                    entry?.threat_score,
                  ),
              }))}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              vertical={false}
              stroke="rgba(148,163,184,0.08)"
            />

            <XAxis
              dataKey="name"
              axisLine={false}
              tickLine={false}
              tick={{
                fill:
                  "#64748b",
                fontSize: 11,
              }}
            />

            <YAxis
              domain={[0, 100]}
              axisLine={false}
              tickLine={false}
              tick={{
                fill:
                  "#64748b",
                fontSize: 11,
              }}
              tickFormatter={(
                value,
              ) =>
                `${value}%`
              }
            />

            <Tooltip
              content={
                <CustomTooltip />
              }
            />

            <Bar
              dataKey="score"
              name="Threat score"
              radius={[
                8,
                8,
                0,
                0,
              ]}
            >
              {history
                .slice(0, 10)
                .map(
                  (
                    entry,
                    index,
                  ) => (
                    <Cell
                      key={
                        entry.id ||
                        index
                      }
                      fill={scoreColour(
                        entry?.threat_score,
                      )}
                    />
                  ),
                )}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </section>
    </main>
  );
}