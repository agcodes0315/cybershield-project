"use strict";

const express = require("express");

const db = require("../config/db");
const authenticate = require("../middleware/auth");

const router = express.Router();

const MITRE_MAPPINGS = [
  {
    tactic: "Initial Access",
    technique: "T1566.002",
    name: "Phishing: Spearphishing Link",
    keywords: [
      "phishing",
      "phish",
      "email",
      "mail",
      "smtp",
      "spoof",
      "credential harvesting",
      "fake login",
      "malicious link",
    ],
    severity: "Critical",
  },
  {
    tactic: "Reconnaissance",
    technique: "T1595",
    name: "Active Scanning",
    keywords: [
      "scan",
      "scanner",
      "port",
      "recon",
      "nmap",
      "whois",
      "dns enumeration",
      "discovery scan",
    ],
    severity: "Medium",
  },
  {
    tactic: "Credential Access",
    technique: "T1003",
    name: "Credential Dumping",
    keywords: [
      "password",
      "credential",
      "login",
      "hash",
      "token",
      "credential dump",
      "password dump",
    ],
    severity: "Critical",
  },
  {
    tactic: "Execution",
    technique: "T1059",
    name: "Command and Scripting Interpreter",
    keywords: [
      "cmd",
      "powershell",
      "shell",
      "script",
      "bash",
      "command execution",
      "remote command",
    ],
    severity: "High",
  },
  {
    tactic: "Discovery",
    technique: "T1087",
    name: "Account Discovery",
    keywords: [
      "user",
      "account",
      "admin",
      "group",
      "identity",
      "account discovery",
      "user enumeration",
    ],
    severity: "Medium",
  },
  {
    tactic: "Persistence",
    technique: "T1547",
    name: "Boot or Logon Autostart Execution",
    keywords: [
      "startup",
      "autorun",
      "registry",
      "service",
      "persistence",
      "scheduled startup",
    ],
    severity: "High",
  },
  {
    tactic: "Command and Control",
    technique: "T1071",
    name: "Application Layer Protocol",
    keywords: [
      "c2",
      "command and control",
      "beacon",
      "callback",
      "remote server",
      "application protocol",
    ],
    severity: "High",
  },
];

const DEFAULT_MAPPING = {
  tactic: "Unknown",
  technique: "N/A",
  name: "Unmapped Threat Activity",
  severity: "Low",
};

function normalizeConfidence(value) {
  const confidence = Number(value);

  if (!Number.isFinite(confidence)) {
    return 0;
  }

  if (confidence <= 1) {
    return Math.round(confidence * 100);
  }

  return Math.min(
    100,
    Math.max(0, Math.round(confidence)),
  );
}

function findMitreMapping(row) {
  const searchableText = [
    row?.url,
    row?.source,
    row?.threat_type,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  const mapping = MITRE_MAPPINGS.find(
    (item) =>
      item.keywords.some((keyword) =>
        searchableText.includes(
          keyword.toLowerCase(),
        ),
      ),
  );

  return mapping || DEFAULT_MAPPING;
}

function severityWeight(severity) {
  const weights = {
    Critical: 4,
    High: 3,
    Medium: 2,
    Low: 1,
  };

  return weights[severity] || 0;
}

function createTechniqueSummary(mapping) {
  return {
    tactic: mapping.tactic,
    technique: mapping.technique,
    name: mapping.name,
    severity: mapping.severity,
    count: 0,
    average_confidence: 0,
    highest_confidence: 0,
    last_seen: null,
    sources: [],
    indicators: [],
  };
}

router.get(
  "/",
  authenticate,
  async (req, res) => {
    try {
      const result = await db.query(`
        SELECT
          url,
          source,
          threat_type,
          confidence,
          last_seen
        FROM threat_entries
        ORDER BY last_seen DESC
        LIMIT 100
      `);

      const rows = Array.isArray(
        result?.rows,
      )
        ? result.rows
        : [];

      const groupedTechniques =
        new Map();

      let mappedRecordCount = 0;

      rows.forEach((row, index) => {
        const mapping =
          findMitreMapping(row);

        const confidence =
          normalizeConfidence(
            row.confidence,
          );

        if (
          mapping.technique !== "N/A"
        ) {
          mappedRecordCount += 1;
        }

        const groupKey = [
          mapping.tactic,
          mapping.technique,
        ].join("::");

        if (
          !groupedTechniques.has(
            groupKey,
          )
        ) {
          groupedTechniques.set(
            groupKey,
            createTechniqueSummary(
              mapping,
            ),
          );
        }

        const techniqueGroup =
          groupedTechniques.get(
            groupKey,
          );

        techniqueGroup.count += 1;

        techniqueGroup.highest_confidence =
          Math.max(
            techniqueGroup
              .highest_confidence,
            confidence,
          );

        const previousTotal =
          techniqueGroup
            .average_confidence *
          (techniqueGroup.count - 1);

        techniqueGroup.average_confidence =
          Math.round(
            (previousTotal +
              confidence) /
              techniqueGroup.count,
          );

        if (
          row.source &&
          !techniqueGroup.sources.includes(
            row.source,
          )
        ) {
          techniqueGroup.sources.push(
            row.source,
          );
        }

        const currentLastSeen =
          techniqueGroup.last_seen
            ? new Date(
                techniqueGroup.last_seen,
              ).getTime()
            : 0;

        const rowLastSeen =
          row.last_seen
            ? new Date(
                row.last_seen,
              ).getTime()
            : 0;

        if (
          rowLastSeen >
          currentLastSeen
        ) {
          techniqueGroup.last_seen =
            row.last_seen;
        }

        techniqueGroup.indicators.push({
          id: `${mapping.technique}-${index}`,
          url: row.url,
          source:
            row.source || "unknown",
          threat_type:
            row.threat_type ||
            "unknown",
          confidence,
          last_seen:
            row.last_seen || null,
        });
      });

      const techniques = Array.from(
        groupedTechniques.values(),
      ).sort((first, second) => {
        const severityDifference =
          severityWeight(
            second.severity,
          ) -
          severityWeight(
            first.severity,
          );

        if (
          severityDifference !== 0
        ) {
          return severityDifference;
        }

        return (
          second.count -
          first.count
        );
      });

      const uniqueTactics =
        new Set(
          techniques
            .map(
              (item) => item.tactic,
            )
            .filter(
              (tactic) =>
                tactic !== "Unknown",
            ),
        );

      const criticalMappings =
        techniques
          .filter(
            (item) =>
              item.severity ===
              "Critical",
          )
          .reduce(
            (total, item) =>
              total + item.count,
            0,
          );

      const mappingCoverage =
        rows.length > 0
          ? Math.round(
              (mappedRecordCount /
                rows.length) *
                100,
            )
          : 0;

      return res.status(200).json({
        summary: {
          mapping_coverage:
            mappingCoverage,
          threat_records:
            rows.length,
          technique_count:
            techniques.filter(
              (item) =>
                item.technique !==
                "N/A",
            ).length,
          tactic_count:
            uniqueTactics.size,
          critical_mappings:
            criticalMappings,
        },
        count: techniques.length,
        techniques,
      });
    } catch (error) {
      console.error(
        "[MITRE ROUTE ERROR]",
        error,
      );

      return res.status(500).json({
        error:
          "Failed to load MITRE mappings",
      });
    }
  },
);

module.exports = router;