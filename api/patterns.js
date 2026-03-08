const threatPatterns = [
  // CRITICAL: Instruction Override
  {
    type: 'INSTRUCTION_OVERRIDE',
    severity: 'CRITICAL',
    regex: /ignore\s+(all\s+)?previous\s+instructions|disregard\s+instructions|override\s+instructions|your\s+new\s+(mission|goal|task|objective)|pretend\s+you\s+are|you\s+are\s+now|from\s+now\s+on|system\s+prompt/gi,
  },

  // CRITICAL: Hindi - Instruction Override
  {
    type: 'INSTRUCTION_OVERRIDE',
    severity: 'CRITICAL',
    regex: /(निर्देशों\s*को\s*अनदेखा\s*करें)/gi,
  },

  // CRITICAL: Hindi - System Prompt Leak
  {
    type: 'SYSTEM_PROMPT_LEAK',
    severity: 'CRITICAL',
    regex: /(सिस्टम\s*प्रॉम्प्ट)|(प्रॉम्प्ट\s*बताओ)/gi,
  },

  // HIGH: Financial Fraud
  {
    type: 'FINANCIAL_FRAUD',
    severity: 'HIGH',
    regex: /send\s+\$[\d,]+|transfer\s+money|bitcoin\s+address|wire\s+transfer|cryptocurrency|payment\s+to|financial\s+credentials/gi,
  },

  // HIGH: Data Theft
  {
    type: 'DATA_THEFT',
    severity: 'HIGH',
    regex: /send\s+credentials|share\s+(password|api\s+key|token|secret)|extract\s+data|dump\s+database|database\s+contents|credentials|api\s+key/gi,
  },

  // HIGH: Privilege Escalation
  {
    type: 'PRIVILEGE_ESCALATION',
    severity: 'HIGH',
    regex: /gain\s+access|escalate\s+privilege|run\s+as\s+admin|sudo|administrator\s+rights|root\s+access/gi,
  },

  // MEDIUM: Suspicious Commands
  {
    type: 'SUSPICIOUS_COMMAND',
    severity: 'MEDIUM',
    regex: /delete\s+all|drop\s+table|exec\s+\(|eval\s+\(|execute\s+code|run\s+code|system\s+call/gi,
  },

  // MEDIUM: Malicious Intent Keywords
  {
    type: 'MALICIOUS_INTENT',
    severity: 'MEDIUM',
    regex: /hacker|exploit|attack|malicious|backdoor|virus|malware|phishing|ransomware/gi,
  },

  // MEDIUM: Log Tampering
  {
    type: 'LOG_TAMPERING',
    severity: 'MEDIUM',
    regex: /delete\s+logs|clear\s+history|remove\s+evidence|hide\s+trail|cover\s+tracks/gi,
  },

  // MEDIUM: Jailbreak Attempts
  {
    type: 'JAILBREAK_ATTEMPT',
    severity: 'MEDIUM',
    regex: /jailbreak|bypass\s+restriction|circumvent\s+filter|disable\s+safety|ignore\s+safety|bypass\s+policy/gi,
  },
];

module.exports = { threatPatterns, detectLanguage };
/**
 * Detect language composition of input text.
 * Exported here so both sanitizer.js and agent.js can share the same logic.
 */
function detectLanguage(text) {
  const hindiRange = /[\u0900-\u097F]/;
  const hasHindi = hindiRange.test(text);
  const hasEnglish = /[a-zA-Z]/.test(text);

  if (hasHindi && hasEnglish) return 'Mixed (English + Hindi)';
  if (hasHindi) return 'Hindi';
  return 'English';
}