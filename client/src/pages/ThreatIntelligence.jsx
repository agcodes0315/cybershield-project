import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  Activity,
  AlertTriangle,
  Clock3,
  Database,
  ExternalLink,
  Filter,
  Globe2,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";

import api, {
  threats,
} from "../services/api";

import "./ThreatIntelligence.css";

const SOURCE_LABELS = {
  phishtank: "PhishTank",
  abusech: "URLhaus",
  urlhaus: "URLhaus",
  openphish: "OpenPhish",
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  unknown: "Unknown",
};

const SOURCE_ORDER = [
  "all",
  "phishtank",
  "abusech",
  "openphish",
  "virustotal",
  "abuseipdb",
  "unknown",
];

function normalizeSource(value) {
  const source = String(value || "unknown")
    .trim()
    .toLowerCase();

  if (source.includes("phish")) {
    if (source.includes("tank")) {
      return "phishtank";
    }

    if (source.includes("open")) {
      return "openphish";
    }
  }

  if (
    source.includes("urlhaus") ||
    source.includes("abuse.ch") ||
    source.includes("abusech")
  ) {
    return "abusech";
  }

  if (source.includes("virus")) {
    return "virustotal";
  }

  if (source.includes("abuseip")) {
    return "abuseipdb";
  }

  return source || "unknown";
}

function sourceLabel(value) {
  const normalized = normalizeSource(value);

  return (
    SOURCE_LABELS[normalized] ||
    normalized
      .replace(/[_-]+/g, " ")
      .replace(/\b\w/g, (letter) =>
        letter.toUpperCase(),
      )
  );
}

function normalizeConfidence(value) {
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

function confidenceBand(value) {
  const confidence =
    normalizeConfidence(value);

  if (confidence >= 85) {
    return {
      label: "Critical",
      color: "#ef4444",
      background:
        "rgba(239, 68, 68, 0.12)",
    };
  }

  if (confidence >= 70) {
    return {
      label: "High",
      color: "#f97316",
      background:
        "rgba(249, 115, 22, 0.12)",
    };
  }

  if (confidence >= 45) {
    return {
      label: "Medium",
      color: "#fbbf24",
      background:
        "rgba(251, 191, 36, 0.12)",
    };
  }

  return {
    label: "Low",
    color: "#34d399",
    background:
      "rgba(52, 211, 153, 0.12)",
  };
}

function formatDate(value) {
  if (!value) {
    return "Unknown";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return date.toLocaleString();
}

function safeJson(value) {
  try {
    return JSON.stringify(
      value || {},
      null,
      2,
    );
  } catch {
    return "{}";
  }
}

function hostnameFromUrl(value) {
  try {
    const candidate = String(value || "");

    const parsed = new URL(
      candidate.startsWith("http")
        ? candidate
        : `https://${candidate}`,
    );

    return parsed.hostname;
  } catch {
    return String(value || "Unknown");
  }
}

function isHttpUrl(value) {
  try {
    const parsed = new URL(value);

    return (
      parsed.protocol === "http:" ||
      parsed.protocol === "https:"
    );
  } catch {
    return false;
  }
}

function normalizeThreatEntry(entry, index) {
  const source = normalizeSource(
    entry?.source,
  );

  const confidence =
    normalizeConfidence(entry?.confidence);

  const threatType = String(
    entry?.threat_type ||
      entry?.type ||
      "unknown",
  );

  return {
    id:
      entry?.id ||
      `${source}-${index}-${entry?.url || "ioc"}`,
    url:
      entry?.url ||
      entry?.indicator ||
      entry?.ioc ||
      "Unknown",
    source,
    sourceLabel: sourceLabel(source),
    threatType,
    confidence,
    firstSeen:
      entry?.first_seen ||
      entry?.created_at ||
      entry?.timestamp ||
      null,
    lastSeen:
      entry?.last_seen ||
      entry?.updated_at ||
      entry?.timestamp ||
      null,
    metadata:
      entry?.metadata &&
      typeof entry.metadata === "object"
        ? entry.metadata
        : {},
    raw: entry,
  };
}

function entryMatchesSearch(
  entry,
  searchValue,
) {
  const query = String(searchValue || "")
    .trim()
    .toLowerCase();

  if (!query) {
    return true;
  }

  return [
    entry.url,
    entry.sourceLabel,
    entry.threatType,
    hostnameFromUrl(entry.url),
    safeJson(entry.metadata),
  ]
    .join(" ")
    .toLowerCase()
    .includes(query);
}

export default function ThreatIntelligence() {
  const [entries, setEntries] =
    useState([]);

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [searching, setSearching] =
    useState(false);

  const [error, setError] =
    useState("");

  const [message, setMessage] =
    useState("");

  const [tableSearch, setTableSearch] =
    useState("");

  const [iocQuery, setIocQuery] =
    useState("");

  const [iocResults, setIocResults] =
    useState([]);

  const [sourceFilter, setSourceFilter] =
    useState("all");

  const [
    severityFilter,
    setSeverityFilter,
  ] = useState("all");

  const [
    selectedEntry,
    setSelectedEntry,
  ] = useState(null);

  const loadRecentThreats =
    useCallback(async () => {
      setError("");

      try {
        const response =
          await threats.recent();

        const payload = response?.data;

        const list = Array.isArray(payload)
          ? payload
          : Array.isArray(payload?.entries)
            ? payload.entries
            : [];

        setEntries(
          list.map(normalizeThreatEntry),
        );
      } catch (requestError) {
        console.error(
          "[Threat Intelligence]",
          requestError,
        );

        setError(
          requestError?.response?.data
            ?.error ||
            "Failed to load threat intelligence data.",
        );
      } finally {
        setLoading(false);
      }
    }, []);

  useEffect(() => {
    loadRecentThreats();
  }, [loadRecentThreats]);

  const refreshFeeds =
    useCallback(async () => {
      setRefreshing(true);
      setError("");
      setMessage("");

      try {
        const response =
          await threats.fetchFeeds();

        const stored =
          response?.data?.stored ?? 0;

        const fetched =
          response?.data?.total_fetched ??
          response?.data?.total ??
          0;

        setMessage(
          `Threat feeds refreshed. ${stored} entries stored from ${fetched} fetched indicators.`,
        );

        await loadRecentThreats();
      } catch (requestError) {
        console.error(
          "[Threat feed refresh]",
          requestError,
        );

        setError(
          requestError?.response?.data
            ?.error ||
            "Failed to refresh threat feeds.",
        );
      } finally {
        setRefreshing(false);
      }
    }, [loadRecentThreats]);

  const searchIOC =
    useCallback(async () => {
      const query = iocQuery.trim();

      if (!query) {
        setIocResults([]);
        setError(
          "Enter a URL, domain, IP address, or IOC to search.",
        );
        return;
      }

      setSearching(true);
      setError("");
      setMessage("");

      try {
        const response = await api.get(
          "/threats/search",
          {
            params: {
              url: query,
            },
          },
        );

        const payload =
          response?.data || {};

        const list = Array.isArray(
          payload.entries,
        )
          ? payload.entries
          : [];

        const normalized = list.map(
          normalizeThreatEntry,
        );

        setIocResults(normalized);

        if (normalized.length === 0) {
          setMessage(
            "No matching indicators were found in the stored threat feeds.",
          );
        } else {
          setMessage(
            `${normalized.length} matching indicator${
              normalized.length === 1
                ? ""
                : "s"
            } found.`,
          );
        }
      } catch (requestError) {
        console.error(
          "[IOC Search]",
          requestError,
        );

        setIocResults([]);

        setError(
          requestError?.response?.data
            ?.error ||
            "IOC search failed.",
        );
      } finally {
        setSearching(false);
      }
    }, [iocQuery]);

  const sourceCounts = useMemo(() => {
    return entries.reduce(
      (accumulator, entry) => {
        accumulator[entry.source] =
          (accumulator[entry.source] ||
            0) + 1;

        return accumulator;
      },
      {},
    );
  }, [entries]);

  const highConfidenceCount =
    useMemo(
      () =>
        entries.filter(
          (entry) =>
            entry.confidence >= 70,
        ).length,
      [entries],
    );

  const criticalCount =
    useMemo(
      () =>
        entries.filter(
          (entry) =>
            entry.confidence >= 85,
        ).length,
      [entries],
    );

  const activeSourceCount =
    useMemo(
      () =>
        Object.keys(sourceCounts).filter(
          (source) =>
            sourceCounts[source] > 0,
        ).length,
      [sourceCounts],
    );

  const latestUpdate = useMemo(() => {
    const timestamps = entries
      .map((entry) =>
        new Date(entry.lastSeen).getTime(),
      )
      .filter(Number.isFinite);

    if (timestamps.length === 0) {
      return null;
    }

    return new Date(
      Math.max(...timestamps),
    );
  }, [entries]);

  const filteredEntries =
    useMemo(() => {
      return entries.filter((entry) => {
        if (
          sourceFilter !== "all" &&
          entry.source !== sourceFilter
        ) {
          return false;
        }

        const severity =
          confidenceBand(
            entry.confidence,
          ).label.toLowerCase();

        if (
          severityFilter !== "all" &&
          severity !== severityFilter
        ) {
          return false;
        }

        return entryMatchesSearch(
          entry,
          tableSearch,
        );
      });
    }, [
      entries,
      sourceFilter,
      severityFilter,
      tableSearch,
    ]);

  const sourceButtons =
    useMemo(() => {
      const availableSources =
        new Set([
          ...Object.keys(sourceCounts),
          "all",
        ]);

      return SOURCE_ORDER.filter(
        (source) =>
          availableSources.has(source),
      );
    }, [sourceCounts]);

  const clearIOCSearch = () => {
    setIocQuery("");
    setIocResults([]);
    setError("");
    setMessage("");
  };

  const openIndicator = (entry) => {
    setSelectedEntry(entry);
  };

  const closeIndicator = () => {
    setSelectedEntry(null);
  };

  return (
    <>
  <div className="ti-page">

    <div className="ti-header">
      <h2>Threat Intelligence Center</h2>
      <p>
        Monitor global threat feeds, investigate indicators of compromise,
        search malicious URLs, and analyse intelligence gathered from
        multiple external providers.
      </p>
    </div>

    {error && (
      <div className="ti-error">
        <AlertTriangle size={16}/>
        {" "}
        {error}
      </div>
    )}

    {message && (
      <div
        style={{
          padding:"14px 18px",
          borderRadius:"12px",
          background:"rgba(52,211,153,.08)",
          border:"1px solid rgba(52,211,153,.18)",
          color:"#34d399",
          fontWeight:600,
          fontSize:".86rem"
        }}
      >
        {message}
      </div>
    )}

    <div className="ti-stats-grid">

      <div className="ti-stat-card">
        <div className="ti-stat-label">
          Total Threat IOCs
        </div>

        <div
          className="ti-stat-value"
          style={{color:"#38bdf8"}}
        >
          {entries.length}
        </div>

        <div className="ti-stat-sub">
          Indicators currently stored
        </div>
      </div>

      <div className="ti-stat-card">
        <div className="ti-stat-label">
          High Confidence
        </div>

        <div
          className="ti-stat-value"
          style={{color:"#f97316"}}
        >
          {highConfidenceCount}
        </div>

        <div className="ti-stat-sub">
          Confidence ≥ 70%
        </div>
      </div>

      <div className="ti-stat-card">
        <div className="ti-stat-label">
          Critical Threats
        </div>

        <div
          className="ti-stat-value"
          style={{color:"#ef4444"}}
        >
          {criticalCount}
        </div>

        <div className="ti-stat-sub">
          Confidence ≥ 85%
        </div>
      </div>

      <div className="ti-stat-card">
        <div className="ti-stat-label">
          Active Sources
        </div>

        <div
          className="ti-stat-value"
          style={{color:"#34d399"}}
        >
          {activeSourceCount}
        </div>

        <div className="ti-stat-sub">
          {latestUpdate
            ? `Updated ${latestUpdate.toLocaleString()}`
            : "No feed updates"}
        </div>

      </div>

    </div>

    <div className="ti-panel">

      <div className="ti-panel-title">

        <div>

          <h3>
            Threat Feed Sources
          </h3>

          <p>
            Intelligence aggregated from external providers.
          </p>

        </div>

        <button
          className="ti-ioc-button"
          onClick={refreshFeeds}
          disabled={refreshing}
        >

          <RefreshCw
            size={16}
            style={{
              marginRight:8,
              animation:refreshing
                ? "spin 1s linear infinite"
                : "none"
            }}
          />

          {
            refreshing
            ? "Refreshing..."
            : "Refresh Feeds"
          }

        </button>

      </div>

      <div className="ti-source-grid">

        {sourceButtons.map((source)=>(
          <div
            key={source}
            className="ti-source-card"
          >

            <div className="name">
              {
                source==="all"
                ? "All Sources"
                : sourceLabel(source)
              }
            </div>

            <div className="count">
              {
                source==="all"
                ? entries.length
                : sourceCounts[source] || 0
              }
            </div>

          </div>
        ))}

      </div>

    </div>

    <div className="ti-panel">

      <div className="ti-panel-title">

        <div>

          <h3>
            IOC Investigation
          </h3>

          <p>
            Search URLs, domains or IP addresses against
            CyberShield threat intelligence.
          </p>

        </div>

      </div>

      <div className="ti-ioc-row">

        <div className="ti-ioc-input">

          <Search
            size={18}
            color="#64748b"
          />

          <input

            value={iocQuery}

            onChange={(e)=>
              setIocQuery(e.target.value)
            }

            placeholder="example.com or https://malicious.site"

            onKeyDown={(e)=>{
              if(e.key==="Enter"){
                searchIOC();
              }
            }}

          />

        </div>

        <button
          className="ti-ioc-button"
          disabled={searching}
          onClick={searchIOC}
        >

          {
            searching
            ? "Searching..."
            : "Search IOC"
          }

        </button>

        <button
          className="ti-ioc-button"
          style={{
            background:"linear-gradient(135deg,#475569,#334155)"
          }}
          onClick={clearIOCSearch}
        >
          <X
            size={16}
            style={{marginRight:8}}
          />
          Clear
        </button>

      </div>

      {iocResults.length>0 && (

        <div className="ti-ioc-results">

          {iocResults.map((ioc)=>{

            const band=
              confidenceBand(ioc.confidence);

            return(

              <div
                key={ioc.id}
                className="ti-ioc-card"
              >

                <h4>

                  {hostnameFromUrl(ioc.url)}

                </h4>
                                <div className="ti-ioc-detail-grid">
                  <div className="ti-ioc-detail">
                    <div className="ti-ioc-detail-label">
                      Indicator
                    </div>
                    <div
                      className="ti-ioc-detail-value"
                      title={ioc.url}
                      style={{
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {ioc.url}
                    </div>
                  </div>

                  <div className="ti-ioc-detail">
                    <div className="ti-ioc-detail-label">
                      Source
                    </div>
                    <div className="ti-ioc-detail-value">
                      {ioc.sourceLabel}
                    </div>
                  </div>

                  <div className="ti-ioc-detail">
                    <div className="ti-ioc-detail-label">
                      Threat Type
                    </div>
                    <div className="ti-ioc-detail-value">
                      {ioc.threatType}
                    </div>
                  </div>

                  <div className="ti-ioc-detail">
                    <div className="ti-ioc-detail-label">
                      Confidence
                    </div>
                    <div
                      className="ti-ioc-detail-value"
                      style={{ color: band.color }}
                    >
                      {Math.round(ioc.confidence)}% · {band.label}
                    </div>
                  </div>

                  <div className="ti-ioc-detail">
                    <div className="ti-ioc-detail-label">
                      First Seen
                    </div>
                    <div className="ti-ioc-detail-value">
                      {formatDate(ioc.firstSeen)}
                    </div>
                  </div>

                  <div className="ti-ioc-detail">
                    <div className="ti-ioc-detail-label">
                      Last Seen
                    </div>
                    <div className="ti-ioc-detail-value">
                      {formatDate(ioc.lastSeen)}
                    </div>
                  </div>
                </div>

                <div
                  style={{
                    display: "flex",
                    gap: "10px",
                    marginTop: "16px",
                    flexWrap: "wrap",
                  }}
                >
                  <span
                    className="ti-badge"
                    style={{
                      color: band.color,
                      background: band.background,
                    }}
                  >
                    {band.label}
                  </span>

                  <button
                    type="button"
                    className="ti-filter-button"
                    onClick={() => openIndicator(ioc)}
                  >
                    View Intelligence
                  </button>

                  {isHttpUrl(ioc.url) && (
                    <a
                      className="ti-filter-button"
                      href={ioc.url}
                      target="_blank"
                      rel="noreferrer"
                      style={{
                        textDecoration: "none",
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "6px",
                      }}
                    >
                      Open IOC
                      <ExternalLink size={13} />
                    </a>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>

    <div className="ti-panel">
      <div className="ti-panel-title">
        <div>
          <h3>Threat Feed Explorer</h3>
          <p>
            Filter, search, and inspect all stored indicators of compromise.
          </p>
        </div>

        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
            color: "var(--text-3)",
            fontSize: "0.78rem",
          }}
        >
          <Activity size={15} />
          {filteredEntries.length} visible indicators
        </div>
      </div>

      <div
        style={{
          display: "flex",
          gap: "12px",
          alignItems: "center",
          flexWrap: "wrap",
          marginBottom: "14px",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            color: "var(--text-3)",
            fontSize: "0.78rem",
            fontWeight: 700,
          }}
        >
          <Filter size={15} />
          Source
        </div>

        <div className="ti-filter-row">
          {sourceButtons.map((source) => (
            <button
              type="button"
              key={source}
              className={`ti-filter-button ${
                sourceFilter === source ? "is-active" : ""
              }`}
              onClick={() => setSourceFilter(source)}
            >
              {source === "all" ? "All Sources" : sourceLabel(source)}
            </button>
          ))}
        </div>
      </div>

      <div
        style={{
          display: "flex",
          gap: "12px",
          alignItems: "center",
          flexWrap: "wrap",
          marginBottom: "18px",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            color: "var(--text-3)",
            fontSize: "0.78rem",
            fontWeight: 700,
          }}
        >
          <ShieldAlert size={15} />
          Severity
        </div>

        <div className="ti-filter-row">
          {["all", "critical", "high", "medium", "low"].map((severity) => (
            <button
              type="button"
              key={severity}
              className={`ti-filter-button ${
                severityFilter === severity ? "is-active" : ""
              }`}
              onClick={() => setSeverityFilter(severity)}
            >
              {severity.charAt(0).toUpperCase() + severity.slice(1)}
            </button>
          ))}
        </div>

        <input
          className="ti-search-input"
          value={tableSearch}
          onChange={(event) => setTableSearch(event.target.value)}
          placeholder="Search IOC, source, domain, or threat type..."
        />
      </div>

      <div style={{ overflowX: "auto" }}>
        <table className="ti-table">
          <thead>
            <tr>
              <th>Indicator</th>
              <th>Source</th>
              <th>Threat Type</th>
              <th>Confidence</th>
              <th>Severity</th>
              <th>Last Seen</th>
              <th>Action</th>
            </tr>
          </thead>

          <tbody>
            {loading ? (
              <tr>
                <td colSpan="7">
                  <div className="ti-empty">
                    <RefreshCw size={22} />
                    <div style={{ marginTop: "10px" }}>
                      Loading threat intelligence...
                    </div>
                  </div>
                </td>
              </tr>
            ) : filteredEntries.length === 0 ? (
              <tr>
                <td colSpan="7">
                  <div className="ti-empty">
                    <Database size={26} />
                    <div style={{ marginTop: "10px", fontWeight: 700 }}>
                      No indicators found
                    </div>
                    <div style={{ marginTop: "5px", fontSize: "0.8rem" }}>
                      Refresh the feeds or change the selected filters.
                    </div>
                  </div>
                </td>
              </tr>
            ) : (
              filteredEntries.map((entry) => {
                const band = confidenceBand(entry.confidence);

                return (
                  <tr key={entry.id}>
                    <td>
                      <div
                        className="ti-cell-mono"
                        title={entry.url}
                        style={{ color: "var(--text-1)", fontWeight: 600 }}
                      >
                        {entry.url}
                      </div>
                    </td>

                    <td>
                      <span
                        className="ti-badge"
                        style={{
                          color: "#38bdf8",
                          background: "rgba(56, 189, 248, 0.1)",
                        }}
                      >
                        {entry.sourceLabel}
                      </span>
                    </td>

                    <td>{entry.threatType}</td>

                    <td>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "10px",
                          minWidth: "130px",
                        }}
                      >
                        <div
                          style={{
                            width: "70px",
                            height: "7px",
                            borderRadius: "999px",
                            overflow: "hidden",
                            background: "var(--bg-input)",
                          }}
                        >
                          <div
                            style={{
                              width: `${entry.confidence}%`,
                              height: "100%",
                              borderRadius: "999px",
                              background: band.color,
                            }}
                          />
                        </div>

                        <span style={{ fontWeight: 700 }}>
                          {Math.round(entry.confidence)}%
                        </span>
                      </div>
                    </td>

                    <td>
                      <span
                        className="ti-badge"
                        style={{
                          color: band.color,
                          background: band.background,
                        }}
                      >
                        {band.label}
                      </span>
                    </td>

                    <td>{formatDate(entry.lastSeen)}</td>

                    <td>
                      <button
                        type="button"
                        className="ti-filter-button"
                        onClick={() => openIndicator(entry)}
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  {selectedEntry && (
    <div
      role="presentation"
      onClick={closeIndicator}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 1000,
        background: "rgba(2, 6, 23, 0.72)",
        backdropFilter: "blur(5px)",
        display: "flex",
        justifyContent: "flex-end",
      }}
    >
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Threat intelligence details"
        onClick={(event) => event.stopPropagation()}
        style={{
          width: "min(560px, 100%)",
          height: "100%",
          overflowY: "auto",
          background: "var(--bg-card)",
          borderLeft: "1px solid var(--border)",
          padding: "26px",
          boxShadow: "-20px 0 60px rgba(0, 0, 0, 0.32)",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            gap: "20px",
            marginBottom: "24px",
          }}
        >
          <div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "9px",
                color: "#38bdf8",
                fontSize: "0.76rem",
                fontWeight: 800,
                textTransform: "uppercase",
                letterSpacing: "0.07em",
                marginBottom: "8px",
              }}
            >
              <Globe2 size={16} />
              IOC Investigation
            </div>

            <h3
              style={{
                margin: 0,
                color: "var(--text-1)",
                fontSize: "1.18rem",
                wordBreak: "break-word",
              }}
            >
              {hostnameFromUrl(selectedEntry.url)}
            </h3>
          </div>

          <button
            type="button"
            className="ti-filter-button"
            onClick={closeIndicator}
            aria-label="Close threat details"
          >
            <X size={17} />
          </button>
        </div>

        <div className="ti-ioc-detail-grid">
          <div className="ti-ioc-detail">
            <div className="ti-ioc-detail-label">Source</div>
            <div className="ti-ioc-detail-value">
              {selectedEntry.sourceLabel}
            </div>
          </div>

          <div className="ti-ioc-detail">
            <div className="ti-ioc-detail-label">Threat Type</div>
            <div className="ti-ioc-detail-value">
              {selectedEntry.threatType}
            </div>
          </div>

          <div className="ti-ioc-detail">
            <div className="ti-ioc-detail-label">Confidence</div>
            <div className="ti-ioc-detail-value">
              {Math.round(selectedEntry.confidence)}%
            </div>
          </div>

          <div className="ti-ioc-detail">
            <div className="ti-ioc-detail-label">Severity</div>
            <div
              className="ti-ioc-detail-value"
              style={{
                color: confidenceBand(selectedEntry.confidence).color,
              }}
            >
              {confidenceBand(selectedEntry.confidence).label}
            </div>
          </div>

          <div className="ti-ioc-detail">
            <div className="ti-ioc-detail-label">First Seen</div>
            <div className="ti-ioc-detail-value">
              {formatDate(selectedEntry.firstSeen)}
            </div>
          </div>

          <div className="ti-ioc-detail">
            <div className="ti-ioc-detail-label">Last Seen</div>
            <div className="ti-ioc-detail-value">
              {formatDate(selectedEntry.lastSeen)}
            </div>
          </div>
        </div>

        <div
          style={{
            marginTop: "18px",
            padding: "16px",
            borderRadius: "12px",
            background: "var(--bg-surface)",
            border: "1px solid var(--border)",
          }}
        >
          <div className="ti-ioc-detail-label">Full Indicator</div>
          <div
            style={{
              marginTop: "7px",
              color: "var(--text-1)",
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: "0.78rem",
              lineHeight: 1.6,
              wordBreak: "break-all",
            }}
          >
            {selectedEntry.url}
          </div>
        </div>

        <div
          style={{
            marginTop: "18px",
            display: "flex",
            gap: "10px",
            flexWrap: "wrap",
          }}
        >
          <span
            className="ti-badge"
            style={{
              color: confidenceBand(selectedEntry.confidence).color,
              background: confidenceBand(selectedEntry.confidence).background,
            }}
          >
            <ShieldCheck size={14} style={{ marginRight: "6px" }} />
            {confidenceBand(selectedEntry.confidence).label} Confidence
          </span>

          <span
            className="ti-badge"
            style={{
              color: "#38bdf8",
              background: "rgba(56, 189, 248, 0.1)",
            }}
          >
            <Clock3 size={14} style={{ marginRight: "6px" }} />
            {formatDate(selectedEntry.lastSeen)}
          </span>
        </div>

        <div style={{ marginTop: "24px" }}>
          <h4
            style={{
              margin: "0 0 10px",
              color: "var(--text-1)",
              fontSize: "0.92rem",
            }}
          >
            Intelligence Metadata
          </h4>

          <pre
            style={{
              margin: 0,
              padding: "16px",
              borderRadius: "12px",
              border: "1px solid var(--border)",
              background: "var(--bg-input)",
              color: "var(--text-2)",
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: "0.74rem",
              lineHeight: 1.65,
              overflowX: "auto",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
            }}
          >
            {safeJson(selectedEntry.metadata)}
          </pre>
        </div>

        <div style={{ marginTop: "18px" }}>
          <h4
            style={{
              margin: "0 0 10px",
              color: "var(--text-1)",
              fontSize: "0.92rem",
            }}
          >
            Raw Feed Record
          </h4>

          <pre
            style={{
              margin: 0,
              padding: "16px",
              borderRadius: "12px",
              border: "1px solid var(--border)",
              background: "var(--bg-input)",
              color: "var(--text-2)",
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: "0.74rem",
              lineHeight: 1.65,
              overflowX: "auto",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
            }}
          >
            {safeJson(selectedEntry.raw)}
          </pre>
        </div>

        {isHttpUrl(selectedEntry.url) && (
          <a
            href={selectedEntry.url}
            target="_blank"
            rel="noreferrer"
            className="ti-ioc-button"
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "8px",
              marginTop: "22px",
              textDecoration: "none",
            }}
          >
            Open Indicator
            <ExternalLink size={16} />
          </a>
        )}
      </aside>
    </div>
  )}
</>
  );
}