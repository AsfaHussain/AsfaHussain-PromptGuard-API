const { threatPatterns, detectLanguage } = require('./patterns');

// ── Source-based risk adjustments ────────────────────────────────────────────
const SOURCE_RISK_ADJUSTMENTS = {
  webpage: 10,
  email: 8,
  pdf: 5,
  text: 0,
};

// ── Metadata-based risk adjustments ──────────────────────────────────────────
const METADATA_RISK_ADJUSTMENTS = {
  containsScript: 10,
  containsExternalLinks: 5,
  suspiciousEncoding: 15,
  hiddenHtmlComments: 8,
};
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Analyze content for security threats.
 *
 * Signature is backwards-compatible: the original single-argument call
 * `analyzeSecurity(content)` still works exactly as before.
 * The two new optional parameters are used by structured-input pipelines.
 *
 * @param {string} content          - Text to analyze
 * @param {string} [source="text"]  - Input source: "webpage"|"email"|"pdf"|"text"
 * @param {Object} [metadata={}]    - Optional metadata from source handlers
 * @returns {Object} Full analysis result
 */
function analyzeSecurity(content, source = 'text', metadata = {}) {
  const threats = [];
  const detailedThreats = [];
  let sanitized = content;
  const originalLength = content.length;

  // ── Language Detection — run BEFORE pattern scan ───────────────────────────
  const detectedLanguage = detectLanguage(content);

  // Scan for all threat patterns (English + Hindi)
  threatPatterns.forEach(pattern => {
    const matches = [...content.matchAll(pattern.regex)];

    matches.forEach(match => {
      threats.push(pattern.type);

      detailedThreats.push({
        type: pattern.type,
        severity: pattern.severity,
        match: match[0],
        position: match.index,
      });

      // Sanitize matched content
      sanitized = sanitized.replace(
        match[0],
        `[🚨 REDACTED: ${pattern.type}]`
      );
    });
  });

  // ── Risk scoring pipeline ──────────────────────────────────────────────────
  const baseRiskScore = calculateRiskScore(detailedThreats);

  const sourceAdjustment = SOURCE_RISK_ADJUSTMENTS[source] ?? 0;

  const metadataAdjustment = calculateMetadataRisk(metadata);

  const finalRiskScore = Math.min(
    baseRiskScore + sourceAdjustment + metadataAdjustment,
    100
  );
  // ───────────────────────────────────────────────────────────────────────────

  const riskLevel = getRiskLevel(finalRiskScore);

  const sanitizedLength = sanitized.length;
  const reduction = (
    ((sanitizedLength - originalLength) / originalLength) * 100
  ).toFixed(2);

  return {
    threats,
    detectedLanguage,
    source,
    metadata,
    baseRiskScore,
    sourceAdjustment,
    metadataAdjustment,
    riskScore: finalRiskScore,
    riskLevel,
    sanitizedContent: sanitized,
    contentReduction: reduction,
    detailedThreats,
  };
}

// ── Threat severity scoring ──────────────────────────────────────────────────
function calculateRiskScore(threats) {
  if (threats.length === 0) return 0;

  const criticalCount = threats.filter(t => t.severity === 'CRITICAL').length;
  const highCount = threats.filter(t => t.severity === 'HIGH').length;
  const mediumCount = threats.filter(t => t.severity === 'MEDIUM').length;

  const score = criticalCount * 25 + highCount * 15 + mediumCount * 5;

  return Math.min(score, 100);
}

// ── Metadata scoring ─────────────────────────────────────────────────────────
function calculateMetadataRisk(metadata = {}) {
  let score = 0;

  Object.keys(metadata).forEach(key => {
    if (metadata[key] && METADATA_RISK_ADJUSTMENTS[key]) {
      score += METADATA_RISK_ADJUSTMENTS[key];
    }
  });

  return score;
}

// ── Risk level classification ────────────────────────────────────────────────
function getRiskLevel(score) {
  if (score === 0) return 'clean';
  if (score < 15) return 'low';
  if (score < 40) return 'medium';
  if (score < 70) return 'high';
  return 'critical';
}

module.exports = {
  analyzeSecurity,
  calculateRiskScore,
  getRiskLevel,
};