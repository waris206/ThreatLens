/**
 * yaraEngine.js — YARA-Lite Signature Scanning Engine
 *
 * A pure-JS regex and byte-pattern matching engine that emulates YARA rule
 * scanning without requiring native YARA compilation (libyara / node-gyp).
 *
 * Each rule contains:
 *   id          – Unique stable identifier (used in reports)
 *   name        – Human-readable title
 *   severity    – 'critical' | 'high' | 'medium' | 'low' | 'info'
 *   description – What the rule detects and why it matters
 *   patterns    – Array of { type: 'string' | 'regex', value }
 *   condition   – 'any' (OR — at least one pattern) | 'all' (AND — every pattern)
 */

// ─── Rule Definitions ───────────────────────────────────────────────────────

const YARA_RULES = [
  // ── 1. Cryptojacking / Miner Wallets ────────────────────────────────────
  {
    id: 'CRYPTO_MINER_WALLET',
    name: 'Cryptocurrency Wallet Address',
    severity: 'critical',
    description:
      'Detects hardcoded cryptocurrency wallet addresses (BTC, ETH, XMR) ' +
      'using strict charset validation (Base58 for BTC — excludes 0, O, I, l).',
    patterns: [
      // Bitcoin Legacy P2PKH (1-prefix, 26-35 chars, strict Base58 charset)
      // MUST contain at least one non-hex Base58 char to avoid matching MD5/SHA hex hashes.
      // Non-hex Base58 chars: G H J K L M N P Q R S T U V W X Y Z a b c d e f g h i j k m n o p q r s t u v w x y z
      { type: 'regex', value: /\b1[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25,34}\b/g,
        validate: (match) => /[GHJKLMNPQRSTUVWXYZghijkmnopqrstuvwxyz]/.test(match) },
      // Bitcoin P2SH (3-prefix, 26-35 chars, strict Base58 charset)
      { type: 'regex', value: /\b3[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25,34}\b/g,
        validate: (match) => /[GHJKLMNPQRSTUVWXYZghijkmnopqrstuvwxyz]/.test(match) },
      // Bitcoin Bech32 (bc1-prefix, lowercase only, 39-59 chars)
      { type: 'regex', value: /\bbc1[a-z0-9]{39,59}\b/g },
      // Ethereum (0x + exactly 40 hex, exclude all-zero)
      { type: 'regex', value: /\b0x(?!0{40})[a-fA-F0-9]{40}\b/g },
      // Monero (4-prefix, 95 chars, strict Base58)
      { type: 'regex', value: /\b4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}\b/g,
        validate: (match) => /[GHJKLMNPQRSTUVWXYZghijkmnopqrstuvwxyz]/.test(match) },
    ],
    condition: 'any',
  },

  // ── 2. Ransomware Indicators ────────────────────────────────────────────
  {
    id: 'RANSOMWARE_INDICATORS',
    name: 'Ransomware Behavior Indicators',
    severity: 'critical',
    description:
      'Detects strings and commands associated with ransomware payloads: ' +
      'ransom notes, shadow-copy deletion, recovery disablement, and .onion C2 domains.',
    patterns: [
      { type: 'string', value: 'Your files have been encrypted' },
      { type: 'string', value: 'vssadmin delete shadows' },
      { type: 'string', value: 'wmic shadowcopy delete' },
      { type: 'string', value: 'bcdedit /set {default} recoveryenabled No' },
      { type: 'regex',  value: /\.onion\b/gi },
      { type: 'string', value: 'DECRYPT_INSTRUCTION' },
      { type: 'string', value: 'YOUR_FILES_ARE_LOCKED' },
      { type: 'regex',  value: /readme_for_decrypt|how_to_decrypt|RECOVERY_FILE/gi },
    ],
    condition: 'any',
  },

  // ── 3. Suspicious Network / C2 Patterns ─────────────────────────────────
  {
    id: 'SUSPICIOUS_NETWORK_C2',
    name: 'Suspicious Network / C2 Indicators',
    severity: 'high',
    description:
      'Detects indicators of Command-and-Control (C2) infrastructure: raw-IP URLs, ' +
      'known staging domains, scripted user-agents, and shell invocation patterns.',
    patterns: [
      // Suspicious user-agents often set by scripts / droppers
      { type: 'regex', value: /User-Agent:\s*(?:Mozilla\/4\.0|curl\/|wget\/|python-requests)/gi },
      // HTTP(S) to raw IP — common C2 beacon pattern
      { type: 'regex', value: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/]/g },
      // Known staging / tunneling services
      { type: 'regex', value: /\b(?:pastebin\.com|raw\.githubusercontent\.com|ngrok\.io|serveo\.net|transfer\.sh)\b/gi },
      // Shell invocation chains
      { type: 'regex', value: /cmd\.exe\s*\/c|powershell(?:\.exe)?\s+-(?:e|enc|encodedcommand)\b/gi },
    ],
    condition: 'any',
  },

  // ── 4. Suspicious PE API Imports (Injection / Hooking / Evasion) ────────
  {
    id: 'PE_SUSPICIOUS_IMPORTS',
    name: 'Process Injection Triad (IAT)',
    severity: 'high',
    requiresPE: true,
    description:
      'Detects the classic process injection triad: VirtualAllocEx + WriteProcessMemory + ' +
      'CreateRemoteThread. ALL THREE must be present to trigger — individual benign APIs are ignored.',
    patterns: [
      { type: 'string', value: 'VirtualAllocEx' },
      { type: 'string', value: 'WriteProcessMemory' },
      { type: 'string', value: 'CreateRemoteThread' },
    ],
    condition: 'all',
  },

  // ── 5. Embedded Script / Macro Payload ──────────────────────────────────
  {
    id: 'EMBEDDED_SCRIPT_PAYLOAD',
    name: 'Embedded Script / Macro Payload',
    severity: 'medium',
    description:
      'Detects embedded scripting payloads (PowerShell encoded commands, VBS/JS ' +
      'droppers, base64-encoded MZ headers) commonly used in weaponised documents.',
    patterns: [
      // PowerShell -EncodedCommand with a long base64 blob
      { type: 'regex', value: /powershell.*-[Ee](?:nc|ncodedcommand)\s+[A-Za-z0-9+\/=]{20,}/gi },
      // Base64-encoded MZ header (PE dropper)
      { type: 'string', value: 'TVqQAAMAAAAEAAAA' },
      // Windows Script Host COM objects
      { type: 'string', value: 'WScript.Shell' },
      { type: 'string', value: 'Scripting.FileSystemObject' },
      // .NET Base64 decode calls
      { type: 'regex', value: /FromBase64String|Convert\.FromBase64/gi },
    ],
    condition: 'any',
  },
];

// ─── Engine ─────────────────────────────────────────────────────────────────

/**
 * Replace non-printable bytes with '.' for safe snippet display.
 */
function sanitizeSnippet(raw) {
  return raw.replace(/[^\x20-\x7E]/g, '.').trim();
}

/**
 * Scan a file buffer against all YARA-Lite rules.
 *
 * @param {Buffer} buffer  Raw file bytes
 * @returns {Array<{
 *   ruleId: string,
 *   ruleName: string,
 *   severity: string,
 *   description: string,
 *   matchCount: number,
 *   matches: Array<{ pattern: string, offset: number, snippet: string }>
 * }>}
 */
export function scanWithYaraRules(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return [];

  // 'binary' encoding preserves all byte values as Latin-1 code-points
  const text = buffer.toString('binary');
  const isPE = buffer.length >= 2 && buffer.readUInt16LE(0) === 0x5A4D;
  const hits = [];

  for (const rule of YARA_RULES) {
    if (rule.requiresPE && !isPE) continue;

    /** @type {Array<{ pattern: string, offset: number, snippet: string, patternIdx: number }>} */
    const ruleMatches = [];

    for (let pIdx = 0; pIdx < rule.patterns.length; pIdx++) {
      const pat = rule.patterns[pIdx];

      if (pat.type === 'string') {
        // Case-insensitive substring search
        const needle   = pat.value.toLowerCase();
        const haystack = text.toLowerCase();
        let pos = 0;

        while ((pos = haystack.indexOf(needle, pos)) !== -1) {
          const ctxStart = Math.max(0, pos - 20);
          const ctxEnd   = Math.min(text.length, pos + needle.length + 20);

          ruleMatches.push({
            pattern: pat.value,
            offset: pos,
            snippet: sanitizeSnippet(text.slice(ctxStart, ctxEnd)),
            patternIdx: pIdx,
          });
          pos += needle.length;
        }
      } else if (pat.type === 'regex') {
        // Clone regex to reset lastIndex safely
        const re = new RegExp(pat.value.source, pat.value.flags);
        const PER_PATTERN_CAP = 10;
        let count = 0;
        let m;

        while ((m = re.exec(text)) !== null && count < PER_PATTERN_CAP) {
          // If pattern has a validate callback, skip matches that fail it
          // (e.g., skip pure-hex strings that aren't real BTC addresses)
          if (typeof pat.validate === 'function' && !pat.validate(m[0])) {
            if (m[0].length === 0) re.lastIndex++;
            continue;
          }

          const ctxStart = Math.max(0, m.index - 20);
          const ctxEnd   = Math.min(text.length, m.index + m[0].length + 20);

          ruleMatches.push({
            pattern: m[0],
            offset: m.index,
            snippet: sanitizeSnippet(text.slice(ctxStart, ctxEnd)),
            patternIdx: pIdx,
          });
          count++;
          if (m[0].length === 0) re.lastIndex++; // prevent infinite loop
        }
      }
    }

    // ── Evaluate rule condition ──────────────────────────────────────────
    let triggered = false;

    if (rule.condition === 'any') {
      triggered = ruleMatches.length > 0;
    } else if (rule.condition === 'all') {
      const uniqueIndices = new Set(ruleMatches.map((m) => m.patternIdx));
      triggered = uniqueIndices.size === rule.patterns.length;
    }

    if (triggered) {
      hits.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        description: rule.description,
        matchCount: ruleMatches.length,
        // Strip internal patternIdx before exposing
        matches: ruleMatches.map(({ pattern, offset, snippet }) => ({
          pattern,
          offset,
          snippet,
        })),
      });
    }
  }

  return hits;
}

/**
 * Return metadata about every loaded rule (useful for UI / documentation).
 */
export function getRuleDefinitions() {
  return YARA_RULES.map((r) => ({
    id: r.id,
    name: r.name,
    severity: r.severity,
    description: r.description,
    patternCount: r.patterns.length,
    condition: r.condition,
    requiresPE: Boolean(r.requiresPE),
  }));
}
