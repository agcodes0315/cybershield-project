import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';

import api from '../services/api';
import './Community.css';

function Panel({ children, className = '' }) {
  return (
    <section
      className={`community-panel ${className}`}
    >
      {children}
    </section>
  );
}

function SoftPanel({
  children,
  className = '',
}) {
  return (
    <div
      className={`community-soft-panel ${className}`}
    >
      {children}
    </div>
  );
}

function Badge({
  label,
  tone = 'neutral',
}) {
  const tones = {
    success: {
      background: 'rgba(34,197,94,0.12)',
      borderColor: 'rgba(34,197,94,0.18)',
      color: '#4ade80',
    },
    danger: {
      background: 'rgba(248,113,113,0.12)',
      borderColor: 'rgba(248,113,113,0.18)',
      color: '#f87171',
    },
    warning: {
      background: 'rgba(251,146,60,0.12)',
      borderColor: 'rgba(251,146,60,0.18)',
      color: '#fb923c',
    },
    info: {
      background: 'rgba(56,189,248,0.12)',
      borderColor: 'rgba(56,189,248,0.18)',
      color: '#38bdf8',
    },
    neutral: {
      background: 'rgba(148,163,184,0.10)',
      borderColor: 'rgba(148,163,184,0.12)',
      color: 'var(--text-secondary)',
    },
  };

  return (
    <span
      className="community-badge"
      style={tones[tone] || tones.neutral}
    >
      {label}
    </span>
  );
}

function StatCard({
  title,
  value,
  subtitle,
  tone = 'info',
}) {
  const colors = {
    danger: '#f87171',
    warning: '#fb923c',
    success: '#4ade80',
    info: '#38bdf8',
  };

  return (
    <SoftPanel>
      <div className="community-score-label">
        {title}
      </div>

      <div
        className="community-stat-value"
        style={{
          color:
            colors[tone] || colors.info,
        }}
      >
        {value}
      </div>

      <div className="community-score-copy">
        {subtitle}
      </div>
    </SoftPanel>
  );
}

function FilterButton({
  active,
  children,
  onClick,
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`community-filter-button ${
        active
          ? 'community-filter-button-active'
          : ''
      }`}
    >
      {children}
    </button>
  );
}

function getHostname(rawUrl) {
  if (!rawUrl) {
    return '';
  }

  try {
    const safeUrl =
      rawUrl.startsWith('http://') ||
      rawUrl.startsWith('https://')
        ? rawUrl
        : `https://${rawUrl}`;

    return new URL(safeUrl).hostname.replace(
      /^www\./,
      '',
    );
  } catch {
    return rawUrl;
  }
}

function computeConfidence(report) {
  const upvotes = Number(
    report.upvotes || 0,
  );

  const downvotes = Number(
    report.downvotes || 0,
  );

  const total = upvotes + downvotes;

  if (total === 0) {
    return 50;
  }

  return Math.round(
    (upvotes / total) * 100,
  );
}

function computeThreatLevel(report) {
  const confidence =
    computeConfidence(report);

  if (report.status === 'verified') {
    return {
      label: 'High Risk',
      score: 85,
    };
  }

  if (report.status === 'dismissed') {
    return {
      label: 'Low Risk',
      score: 20,
    };
  }

  if (confidence >= 75) {
    return {
      label: 'Elevated',
      score: 70,
    };
  }

  if (confidence >= 55) {
    return {
      label: 'Moderate',
      score: 50,
    };
  }

  return {
    label: 'Unreviewed',
    score: 30,
  };
}

function getReportTone(status, score) {
  if (status === 'verified') {
    return 'danger';
  }

  if (status === 'dismissed') {
    return 'success';
  }

  if (score >= 70) {
    return 'danger';
  }

  if (score >= 45) {
    return 'warning';
  }

  return 'info';
}

function getToneStyle(tone) {
  const styles = {
    danger: {
      background:
        'rgba(248,113,113,0.12)',
      color: '#f87171',
    },
    warning: {
      background:
        'rgba(251,146,60,0.12)',
      color: '#fb923c',
    },
    success: {
      background:
        'rgba(34,197,94,0.12)',
      color: '#4ade80',
    },
    info: {
      background:
        'rgba(56,189,248,0.12)',
      color: '#38bdf8',
    },
  };

  return styles[tone] || styles.info;
}

function ReportCard({
  report,
  onVote,
}) {
  const domain = getHostname(report.url);
  const confidence =
    computeConfidence(report);

  const threat =
    computeThreatLevel(report);

  const tone = getReportTone(
    report.status,
    threat.score,
  );

  return (
    <SoftPanel className="community-report-card">
      <div className="community-report-main">
        <div className="community-report-title-row">
          <div
            className="community-report-icon"
            style={getToneStyle(tone)}
          >
            🌐
          </div>

          <div className="community-report-copy">
            <div className="community-report-domain">
              {domain || 'Unknown domain'}
            </div>

            <div className="community-report-url">
              {report.url}
            </div>
          </div>
        </div>

        <div className="community-badge-row">
          <Badge
            label={
              report.status || 'pending'
            }
            tone={
              report.status === 'verified'
                ? 'danger'
                : report.status ===
                    'dismissed'
                  ? 'success'
                  : 'warning'
            }
          />

          <Badge
            label={threat.label}
            tone={tone}
          />

          <Badge
            label={`Confidence ${confidence}%`}
            tone="info"
          />
        </div>

        <div className="community-report-reason">
          {report.reason ||
            'No reason was added for this report.'}
        </div>

        <div className="community-report-meta">
          <span>
            Created:{' '}
            {report.created_at
              ? new Date(
                  report.created_at,
                ).toLocaleDateString()
              : 'Unknown'}
          </span>

          <span>
            Upvotes: {report.upvotes || 0}
          </span>

          <span>
            Downvotes:{' '}
            {report.downvotes || 0}
          </span>
        </div>
      </div>

      <div className="community-report-side">
        <div className="community-score-card">
          <div className="community-score-label">
            Community Score
          </div>

          <div className="community-score-value">
            {confidence}%
          </div>

          <div className="community-score-copy">
            Based on community voting
          </div>
        </div>

        <div className="community-vote-row">
          <button
            type="button"
            className="
              community-vote-button
              community-vote-trust
            "
            onClick={() =>
              onVote(report.id, 'up')
            }
          >
            ▲ Trust
          </button>

          <button
            type="button"
            className="
              community-vote-button
              community-vote-doubt
            "
            onClick={() =>
              onVote(report.id, 'down')
            }
          >
            ▼ Doubt
          </button>
        </div>
      </div>
    </SoftPanel>
  );
}

export default function Community() {
  const [reports, setReports] =
    useState([]);

  const [url, setUrl] =
    useState('');

  const [reason, setReason] =
    useState('');

  const [submitting, setSubmitting] =
    useState(false);

  const [message, setMessage] =
    useState('');

  const [search, setSearch] =
    useState('');

  const [filter, setFilter] =
    useState('all');

  const loadReports = useCallback(
    async () => {
      try {
        const response = await api.get(
          '/community/reports',
        );

        setReports(
          Array.isArray(response.data)
            ? response.data
            : [],
        );
      } catch {
        setReports([]);
      }
    },
    [],
  );

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  const submitReport = async () => {
    if (!url.trim()) {
      setMessage(
        'Please enter a suspicious URL.',
      );
      return;
    }

    setSubmitting(true);
    setMessage('');

    try {
      await api.post(
        '/community/report',
        {
          url: url.trim(),
          reason: reason.trim(),
        },
      );

      setMessage(
        'Report submitted successfully.',
      );

      setUrl('');
      setReason('');

      await loadReports();
    } catch (error) {
      setMessage(
        error.response?.data?.error ||
          'Failed to submit report.',
      );
    } finally {
      setSubmitting(false);
    }
  };

  const vote = async (id, type) => {
    try {
      await api.post(
        `/community/report/${id}/vote`,
        { type },
      );

      await loadReports();
    } catch {
      setMessage(
        'Your vote could not be recorded.',
      );
    }
  };

  const filteredReports = useMemo(() => {
    let list = [...reports];

    if (search.trim()) {
      const query =
        search.trim().toLowerCase();

      list = list.filter((report) =>
        [
          report.url,
          report.reason,
          report.status,
          getHostname(report.url),
        ]
          .filter(Boolean)
          .some((value) =>
            String(value)
              .toLowerCase()
              .includes(query),
          ),
      );
    }

    if (filter === 'verified') {
      list = list.filter(
        (report) =>
          report.status === 'verified',
      );
    }

    if (filter === 'dismissed') {
      list = list.filter(
        (report) =>
          report.status === 'dismissed',
      );
    }

    if (filter === 'pending') {
      list = list.filter(
        (report) =>
          report.status !== 'verified' &&
          report.status !== 'dismissed',
      );
    }

    if (filter === 'high-confidence') {
      list = list.filter(
        (report) =>
          computeConfidence(report) >= 70,
      );
    }

    return list.sort((a, b) => {
      const aScore =
        Number(a.upvotes || 0) -
        Number(a.downvotes || 0);

      const bScore =
        Number(b.upvotes || 0) -
        Number(b.downvotes || 0);

      return bScore - aScore;
    });
  }, [reports, search, filter]);

  const stats = useMemo(() => {
    const total = reports.length;

    const verified = reports.filter(
      (report) =>
        report.status === 'verified',
    ).length;

    const dismissed = reports.filter(
      (report) =>
        report.status === 'dismissed',
    ).length;

    const pending =
      total - verified - dismissed;

    const highConfidence =
      reports.filter(
        (report) =>
          computeConfidence(report) >= 70,
      ).length;

    return {
      total,
      verified,
      pending,
      highConfidence,
    };
  }, [reports]);

  return (
    <div className="community-page">
      <Panel>
        <div className="community-overview-grid">
          <div>
            <div
              style={{
                marginBottom: '18px',
              }}
            >
              <h2 className="community-heading">
                Community Threat Intelligence
              </h2>

              <p className="community-description">
                Report suspicious URLs,
                review community findings and
                build a shared phishing
                intelligence feed.
              </p>
            </div>

            <div className="community-stats-grid">
              <StatCard
                title="Total Reports"
                value={stats.total}
                subtitle="All submitted URLs"
              />

              <StatCard
                title="Verified Threats"
                value={stats.verified}
                subtitle="Marked malicious by review"
                tone="danger"
              />

              <StatCard
                title="Pending Review"
                value={stats.pending}
                subtitle="Awaiting stronger validation"
                tone="warning"
              />

              <StatCard
                title="High Confidence"
                value={stats.highConfidence}
                subtitle="Strong community agreement"
                tone="success"
              />
            </div>
          </div>

          <SoftPanel>
            <div className="community-section-title">
              How this works
            </div>

            <div className="community-how-list">
              <div>
                1. Submit a suspicious website
                or phishing page.
              </div>

              <div>
                2. Community members vote to
                increase or reduce trust.
              </div>

              <div>
                3. Reports become more useful
                as more analysts interact with
                them.
              </div>

              <div>
                4. With one user, it also works
                as a personal threat log.
              </div>
            </div>

            <div
              className="community-badge-row"
              style={{
                marginTop: '16px',
              }}
            >
              <Badge
                label="Shared Intelligence"
                tone="info"
              />

              <Badge
                label="Voting Enabled"
                tone="warning"
              />

              <Badge
                label="Phishing Reports"
                tone="danger"
              />
            </div>
          </SoftPanel>
        </div>
      </Panel>

      <div className="community-form-filter-grid">
        <Panel>
          <div className="community-section-title">
            Submit Suspicious URL
          </div>

          <div className="community-form">
            <div>
              <label className="community-field-label">
                Suspicious URL
              </label>

              <input
                className="community-input"
                value={url}
                onChange={(event) =>
                  setUrl(event.target.value)
                }
                placeholder="https://suspicious-website.com"
              />
            </div>

            <div>
              <label className="community-field-label">
                Why is it suspicious?
              </label>

              <textarea
                className="community-textarea"
                value={reason}
                onChange={(event) =>
                  setReason(
                    event.target.value,
                  )
                }
                placeholder="Example: fake login page, urgency scam, typo-squatted domain or suspicious redirect..."
                rows={5}
              />
            </div>

            <button
              type="button"
              className="community-submit-button"
              onClick={submitReport}
              disabled={submitting}
            >
              {submitting
                ? 'Submitting...'
                : 'Submit Threat Report'}
            </button>

            {message && (
              <div className="community-message">
                {message}
              </div>
            )}
          </div>
        </Panel>

        <Panel>
          <div className="community-section-title">
            Search & Filter Threat Feed
          </div>

          <div className="community-form">
            <input
              className="community-input"
              value={search}
              onChange={(event) =>
                setSearch(
                  event.target.value,
                )
              }
              placeholder="Search by domain, URL, reason or status..."
            />

            <div className="community-filter-row">
              <FilterButton
                active={filter === 'all'}
                onClick={() =>
                  setFilter('all')
                }
              >
                All
              </FilterButton>

              <FilterButton
                active={
                  filter === 'verified'
                }
                onClick={() =>
                  setFilter('verified')
                }
              >
                Verified
              </FilterButton>

              <FilterButton
                active={
                  filter === 'pending'
                }
                onClick={() =>
                  setFilter('pending')
                }
              >
                Pending
              </FilterButton>

              <FilterButton
                active={
                  filter === 'dismissed'
                }
                onClick={() =>
                  setFilter('dismissed')
                }
              >
                Dismissed
              </FilterButton>

              <FilterButton
                active={
                  filter ===
                  'high-confidence'
                }
                onClick={() =>
                  setFilter(
                    'high-confidence',
                  )
                }
              >
                High Confidence
              </FilterButton>
            </div>

            <div className="community-results-count">
              Showing{' '}
              {filteredReports.length} of{' '}
              {reports.length} reports
            </div>
          </div>
        </Panel>
      </div>

      <Panel>
        <div className="community-feed-header">
          <div>
            <div
              className="community-section-title"
              style={{
                marginBottom: '6px',
              }}
            >
              Community Threat Feed
            </div>

            <div className="community-description">
              Shared suspicious URL reports
              ranked by community validation
            </div>
          </div>

          <Badge
            label={`${filteredReports.length} visible reports`}
            tone="info"
          />
        </div>

        {filteredReports.length > 0 ? (
          <div className="community-feed-list">
            {filteredReports.map(
              (report) => (
                <ReportCard
                  key={report.id}
                  report={report}
                  onVote={vote}
                />
              ),
            )}
          </div>
        ) : (
          <div className="community-empty-state">
            <div className="community-empty-title">
              No matching community reports
            </div>

            <div className="community-empty-copy">
              Change the filters, clear the
              search or submit the first
              suspicious URL.
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}