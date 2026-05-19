/**
 * ThreatLens v2 — Hard Risk Scorer
 *
 * Deterministic, pre-AI numeric risk scoring.
 * Runs BEFORE any LLM call so that AI agents receive a BINDING
 * risk classification they must explain, not invent.
 *
 * Score bands:
 *   < 20  → LOW
 *   20–60 → SUSPICIOUS
 *   > 60  → HIGH
 */

// ─── Magic-byte → expected file type mapping ────────────────────────────────
const MAGIC_MAP = [
  { hex: '4D5A',         type: 'exe' },   // MZ → PE executable
  { hex: '25504446',     type: 'pdf' },   // %PDF
  { hex: '504B0304',     type: 'zip' },   // PK.. (zip / docx / xlsx / apk)
  { hex: '504B0506',     type: 'zip' },
  { hex: '504B0708',     type: 'zip' },
  { hex: '89504E47',     type: 'png' },   // .PNG
  { hex: 'FFD8FF',       type: 'jpg' },   // JPEG
  { hex: '47494638',     type: 'gif' },   // GIF8
  { hex: '52494646',     type: 'avi' },   // RIFF (avi / wav / webp)
  { hex: '1F8B08',       type: 'gz' },    // gzip
  { hex: '377ABCAF271C', type: '7z' },    // 7-Zip
  { hex: '7F454C46',     type: 'elf' },   // ELF binary
  { hex: 'CAFEBABE',     type: 'class' }, // Java class / Mach-O fat
  { hex: 'D0CF11E0',     type: 'doc' },   // OLE2 (doc / xls / ppt)
];

// Extension alias groups — extensions that share the same underlying format
const EXT_ALIASES = {
  exe:  ['exe', 'dll', 'sys', 'scr', 'ocx', 'cpl'],
  zip:  ['zip', 'docx', 'xlsx', 'pptx', 'odt', 'jar', 'apk', 'xpi'],
  jpg:  ['jpg', 'jpeg', 'jpe', 'jfif'],
  doc:  ['doc', 'xls', 'ppt', 'msi'],
  gz:   ['gz', 'tgz'],
  avi:  ['avi', 'wav', 'webp'],
};

/**
 * Map raw magic-bytes hex string to a canonical file type.
 */
function magicToType(magicHex) {
  if (!magicHex) return null;
  const clean = magicHex.replace(/\s+/g, '').toUpperCase();
  for (const entry of MAGIC_MAP) {
    if (clean.startsWith(entry.hex)) return entry.type;
  }
  return null;
}

/**
 * Check whether claimed extension and magic-byte type are compatible.
 */
function extensionsMatch(claimedExt, magicType) {
  if (!claimedExt || !magicType) return true; // can't determine → no penalty
  const ext = claimedExt.toLowerCase();
  if (ext === magicType) return true;

  // Check alias groups
  for (const aliases of Object.values(EXT_ALIASES)) {
    if (aliases.includes(ext) && aliases.includes(magicType)) return true;
  }
  return false;
}

// ─── IAT API Classification ─────────────────────────────────────────────────

const HIGH_RISK_APIS = new Set([
  'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
  'NtCreateThreadEx', 'RtlCreateUserThread',
  'SetWindowsHookExA', 'SetWindowsHookExW',
  'CryptEncrypt',
  'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW',
  'HttpSendRequestA', 'HttpSendRequestW',
  'URLDownloadToFileA', 'URLDownloadToFileW',
]);

const ANTI_ANALYSIS_APIS = new Set([
  'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
  'NtQueryInformationProcess', 'GetTickCount',
]);

const INJECTION_TRIAD = ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'];

/**
 * Classify a PE's IAT imports and return risk signals.
 */
function classifyImports(peAnalysis) {
  const result = {
    classification: 'BENIGN',
    hasInjectionTriad: false,
    highRiskApis: [],
    antiAnalysisApis: [],
  };

  if (!peAnalysis?.isPE || !Array.isArray(peAnalysis.imports)) return result;

  const allFunctions = new Set();
  for (const imp of peAnalysis.imports) {
    for (const fn of imp.functions) {
      allFunctions.add(fn);
    }
  }

  // Check injection triad (all three must be present)
  result.hasInjectionTriad = INJECTION_TRIAD.every(api => allFunctions.has(api));

  // Collect high-risk and anti-analysis hits
  for (const api of allFunctions) {
    if (HIGH_RISK_APIS.has(api)) result.highRiskApis.push(api);
    if (ANTI_ANALYSIS_APIS.has(api)) result.antiAnalysisApis.push(api);
  }

  if (result.hasInjectionTriad) {
    result.classification = 'CRITICAL — Injection Triad Present';
  } else if (result.highRiskApis.length > 0) {
    result.classification = 'HIGH-RISK APIs detected';
  } else if (result.antiAnalysisApis.length > 0) {
    result.classification = 'ANTI-ANALYSIS APIs detected';
  }

  return result;
}

// ─── Compressed / high-entropy formats ───────────────────────────────────────
const HIGH_ENTROPY_FORMATS = new Set([
  'zip', 'gz', '7z', 'png', 'jpg', 'gif', 'pdf', 'avi',
  'mp3', 'mp4', 'webp', 'webm', 'flac', 'ogg',
]);

// ─── Main Scoring Function ──────────────────────────────────────────────────

/**
 * Calculate a deterministic hard risk score for a file.
 *
 * @param {object} params
 * @param {string} params.claimedExtension  e.g. 'pdf'
 * @param {string} params.magicBytes        e.g. '4D 5A 90 00'
 * @param {string|number} params.entropy    Shannon entropy (0-8)
 * @param {{ malicious: number, undetected: number }} params.virusTotal
 * @param {{ matchCount: number, knownMalware: boolean, malwareFamilies: string[] }} params.yaraify
 * @param {{ found: boolean }} params.malwareBazaar
 * @param {{ detectedBehaviors: string[] }} params.sandbox
 * @param {{ signed: boolean, trusted: boolean }} params.digitalSignature
 * @param {object} params.peAnalysis        from peParser.js
 * @param {Array}  params.yaraHits          from yaraEngine.js
 *
 * @returns {{ score: number, label: string, breakdown: Array, iatClassification: string }}
 */
export function calculateRiskScore({
  claimedExtension = '',
  magicBytes = '',
  entropy = 0,
  virusTotal = {},
  yaraify = {},
  malwareBazaar = {},
  sandbox = {},
  digitalSignature = {},
  peAnalysis = {},
  yaraHits = [],
}) {
  let score = 0;
  const breakdown = [];
  const entropyVal = parseFloat(entropy) || 0;
  const magicType = magicToType(magicBytes);

  // ── 1. Extension Mismatch ───────────────────────────────────────────────
  if (claimedExtension && magicType && !extensionsMatch(claimedExtension, magicType)) {
    score += 30;
    breakdown.push({
      signal: 'EXTENSION_MISMATCH',
      delta: +30,
      reason: `Claimed .${claimedExtension} but magic bytes indicate ${magicType}`,
    });
  }

  // ── 2. Digital Signature ────────────────────────────────────────────────
  if (digitalSignature?.signed && digitalSignature?.trusted) {
    score -= 50;
    breakdown.push({
      signal: 'TRUSTED_SIGNATURE',
      delta: -50,
      reason: `Signed by trusted vendor: ${digitalSignature.publisher}`,
    });
  } else if (digitalSignature?.signed && !digitalSignature?.trusted) {
    score -= 10;
    breakdown.push({
      signal: 'UNTRUSTED_SIGNATURE',
      delta: -10,
      reason: `Signed by: ${digitalSignature.publisher} (not in trusted list)`,
    });
  } else if (peAnalysis?.isPE) {
    score += 20;
    breakdown.push({
      signal: 'UNSIGNED_PE',
      delta: +20,
      reason: 'PE executable with no digital signature',
    });
  }

  // ── 3. VirusTotal ──────────────────────────────────────────────────────
  const vtMal = virusTotal?.malicious ?? 0;
  const vtClean = virusTotal?.undetected ?? 0;

  if (vtMal === 0 && vtClean > 0) {
    score -= 20;
    breakdown.push({
      signal: 'VT_CLEAN',
      delta: -20,
      reason: `0 malicious detections, ${vtClean} clean`,
    });
  } else if (vtMal > 0 && vtMal <= 3) {
    score += 20;
    breakdown.push({
      signal: 'VT_LOW_DETECT',
      delta: +20,
      reason: `${vtMal} malicious detections (low)`,
    });
  } else if (vtMal > 3 && vtMal <= 10) {
    score += 40;
    breakdown.push({
      signal: 'VT_MED_DETECT',
      delta: +40,
      reason: `${vtMal} malicious detections (medium)`,
    });
  } else if (vtMal > 10) {
    score += 60;
    breakdown.push({
      signal: 'VT_HIGH_DETECT',
      delta: +60,
      reason: `${vtMal} malicious detections (high)`,
    });
  }

  // ── 4. Entropy ─────────────────────────────────────────────────────────
  const isCompressedFormat = HIGH_ENTROPY_FORMATS.has(claimedExtension?.toLowerCase())
    || HIGH_ENTROPY_FORMATS.has(magicType);

  if (entropyVal >= 7.2 && !isCompressedFormat) {
    score += 15;
    breakdown.push({
      signal: 'HIGH_ENTROPY',
      delta: +15,
      reason: `Entropy ${entropyVal} in non-compressed format — possible packing/encryption`,
    });
  } else if (entropyVal <= 3.5 && peAnalysis?.isPE) {
    score -= 5;
    breakdown.push({
      signal: 'LOW_PE_ENTROPY',
      delta: -5,
      reason: `Low entropy (${entropyVal}) — not packed or encrypted`,
    });
  }

  // ── 5. YARA Hits ───────────────────────────────────────────────────────
  if (Array.isArray(yaraHits) && yaraHits.length > 0) {
    const maxSeverity = yaraHits.reduce((max, h) => {
      const sev = (h.severity || '').toLowerCase();
      if (sev === 'critical') return 'critical';
      if (sev === 'high' && max !== 'critical') return 'high';
      if (sev === 'medium' && max === 'none') return 'medium';
      return max;
    }, 'none');

    const yaraDeltas = { critical: 35, high: 25, medium: 15 };
    const delta = yaraDeltas[maxSeverity] || 10;
    score += delta;
    breakdown.push({
      signal: 'YARA_HIT',
      delta: +delta,
      reason: `YARA: ${yaraHits.length} rule(s) triggered (max severity: ${maxSeverity})`,
    });
  } else {
    score -= 10;
    breakdown.push({
      signal: 'YARA_CLEAN',
      delta: -10,
      reason: 'No YARA-Lite rules triggered',
    });
  }

  // ── 6. IAT Classification ──────────────────────────────────────────────
  const iat = classifyImports(peAnalysis);

  if (iat.hasInjectionTriad) {
    score += 40;
    breakdown.push({
      signal: 'INJECTION_TRIAD',
      delta: +40,
      reason: 'Process injection triad: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread',
    });
  } else if (iat.highRiskApis.length > 0) {
    score += 15;
    breakdown.push({
      signal: 'HIGH_RISK_APIS',
      delta: +15,
      reason: `High-risk APIs: ${iat.highRiskApis.join(', ')}`,
    });
  }

  if (iat.antiAnalysisApis.length > 0) {
    score += 10;
    breakdown.push({
      signal: 'ANTI_ANALYSIS',
      delta: +10,
      reason: `Anti-analysis APIs: ${iat.antiAnalysisApis.join(', ')}`,
    });
  }

  // ── Final classification ───────────────────────────────────────────────
  // --- 7. YARAify Community Signals ---
  const yaraifyMatchCount = yaraify?.matchCount ?? 0;
  const yaraifyFamilies = Array.isArray(yaraify?.malwareFamilies) ? yaraify.malwareFamilies : [];

  /**
   * YARAIFY_RULE_MATCH adds +30 when abuse.ch YARAify returns any community
   * YARA hit. This is stronger than local YARA-Lite because it reflects a
   * curated public ruleset, but it remains below confirmed malware reputation.
   */
  if (yaraifyMatchCount > 0) {
    score += 30;
    breakdown.push({
      signal: 'YARAIFY_RULE_MATCH',
      delta: +30,
      confidence: 'HIGH',
      reason: `YARAify returned ${yaraifyMatchCount} community rule match(es)`,
    });
  }

  /**
   * YARAIFY_MULTI_MATCH adds +20 when more than five YARAify rules match,
   * indicating independent signatures are converging on the same sample.
   */
  if (yaraifyMatchCount > 5) {
    score += 20;
    breakdown.push({
      signal: 'YARAIFY_MULTI_MATCH',
      delta: +20,
      confidence: 'HIGH',
      reason: `YARAify returned ${yaraifyMatchCount} matches (>5 threshold)`,
    });
  }

  /**
   * YARAIFY_KNOWN_MALWARE adds +25 when YARAify/ClamAV context identifies the
   * sample as known malware. This is reputation-backed but still separate from
   * MalwareBazaar's explicit malware database confirmation.
   */
  if (yaraify?.knownMalware) {
    score += 25;
    breakdown.push({
      signal: 'YARAIFY_KNOWN_MALWARE',
      delta: +25,
      confidence: 'HIGH',
      reason: 'YARAify indicates the sample is known malware',
    });
  }

  /**
   * YARAIFY_HIGH_IMPACT_FAMILY adds +20 when YARAify family tags include
   * ransomware, RAT, stealer, or loader labels. These families are operationally
   * high-impact and should be surfaced even before AI explanation.
   */
  if (yaraifyFamilies.some((family) => ['ransomware', 'rat', 'stealer', 'loader'].includes(String(family).toLowerCase()))) {
    score += 20;
    breakdown.push({
      signal: 'YARAIFY_HIGH_IMPACT_FAMILY',
      delta: +20,
      confidence: 'HIGH',
      reason: `High-impact malware family tag(s): ${yaraifyFamilies.join(', ')}`,
    });
  }

  // --- 8. MalwareBazaar Confirmed Malware ---
  /**
   * KNOWN_MALWARE_CONFIRMED adds +60 when MalwareBazaar confirms the SHA-256
   * hash exists in its malware database. This is the highest-confidence v3
   * positive signal because it is an explicit known-malware reputation match.
   */
  if (malwareBazaar?.found) {
    score += 60;
    breakdown.push({
      signal: 'KNOWN_MALWARE_CONFIRMED',
      delta: +60,
      confidence: 'CRITICAL',
      reason: 'MalwareBazaar confirms this hash as known malware',
    });
  }

  // --- 9. Simulated Sandbox Behaviors ---
  const sandboxWeights = {
    PROCESS_INJECTION: 35,
    PERSISTENCE: 25,
    DEFENSE_EVASION: 20,
    CREDENTIAL_ACCESS: 30,
    RANSOMWARE_INDICATORS: 40,
    NETWORK_COMMUNICATION: 15,
  };
  const sandboxBehaviors = Array.isArray(sandbox?.detectedBehaviors) ? sandbox.detectedBehaviors : [];

  for (const [behavior, weight] of Object.entries(sandboxWeights)) {
    /**
     * SANDBOX_BEHAVIOR signals add deterministic weight for PE imports that
     * map to malware-like runtime behaviors. The sandbox is simulated static
     * analysis, so each delta is explainable from imports and cannot be AI-set.
     */
    if (sandboxBehaviors.includes(behavior)) {
      score += weight;
      breakdown.push({
        signal: `SANDBOX_${behavior}`,
        delta: +weight,
        confidence: 'MEDIUM',
        reason: `Simulated sandbox detected ${behavior.replace(/_/g, ' ').toLowerCase()} behavior`,
      });
    }
  }

  score = Math.min(100, Math.max(0, score));

  let label;
  if (score < 20) label = 'LOW';
  else if (score <= 60) label = 'SUSPICIOUS';
  else label = 'HIGH';

  return {
    score,
    label,
    breakdown,
    iatClassification: iat.classification,
  };
}
