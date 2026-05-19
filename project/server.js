import 'dotenv/config';
import express from 'express';
import multer from 'multer';
import cors from 'cors';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const { dirname, join } = path;
import { marked } from 'marked';
import helmet from 'helmet';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { calculateShannonEntropy, extractMagicBytes, extractStrings, extractMetadata, checkSignature } from './forensics.js';
import { parseImportTable } from './peParser.js';
import { scanWithYaraRules } from './yaraEngine.js';
import { calculateRiskScore } from './riskScorer.js';
import { scanWithYaraify } from './forensics/yaraifyScanner.js';
import { lookupMalwareBazaar } from './forensics/malwareBazaar.js';
import { analyzeSandboxBehavior } from './forensics/sandboxAnalyzer.js';
import { isEmlFile, parseEml } from './forensics/emlParser.js';
import { sendHighRiskAlert } from './utils/webhookAlerter.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = 5000;

// Load environment variables
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const SERVER_URL = process.env.SERVER_URL || `http://localhost:${PORT}`;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const ADMIN_PIN = process.env.ADMIN_PIN || '1337';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || crypto.randomBytes(32).toString('hex');
const PUBLIC_API_KEY = process.env.API_KEY || '';

const analysisStore = new Map();

/**
 * Generate styled HTML report from Markdown content
 * @param {string} markdownContent - The Markdown content to convert
 * @returns {string} Complete HTML document string
 */
function generateHTMLReport(markdownContent) {
  const htmlContent = marked.parse(markdownContent);
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forensic Analysis Report</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      max-width: 800px;
      margin: 2rem auto;
      padding: 0 1rem;
      line-height: 1.6;
      color: #333;
      background-color: #fff;
    }
    h1, h2, h3, h4, h5, h6 {
      color: #222;
      margin-top: 1.5em;
      margin-bottom: 0.5em;
    }
    h1 {
      border-bottom: 2px solid #333;
      padding-bottom: 0.3em;
    }
    h2 {
      border-bottom: 1px solid #ccc;
      padding-bottom: 0.3em;
    }
    p {
      margin: 1em 0;
    }
    code {
      background-color: #f4f4f4;
      padding: 0.2em 0.4em;
      border-radius: 3px;
      font-family: 'Courier New', monospace;
      font-size: 0.9em;
    }
    pre {
      background-color: #f4f4f4;
      padding: 1em;
      border-radius: 5px;
      overflow-x: auto;
      border: 1px solid #ddd;
    }
    pre code {
      background-color: transparent;
      padding: 0;
    }
    table {
      border-collapse: collapse;
      width: 100%;
      margin: 1em 0;
      border: 1px solid #ddd;
    }
    th, td {
      border: 1px solid #ddd;
      padding: 0.75em;
      text-align: left;
    }
    th {
      background-color: #f2f2f2;
      font-weight: bold;
    }
    tr:nth-child(even) {
      background-color: #f9f9f9;
    }
    ul, ol {
      margin: 1em 0;
      padding-left: 2em;
    }
    li {
      margin: 0.5em 0;
    }
    blockquote {
      border-left: 4px solid #ddd;
      margin: 1em 0;
      padding-left: 1em;
      color: #666;
    }
    hr {
      border: none;
      border-top: 1px solid #ddd;
      margin: 2em 0;
    }
  </style>
</head>
<body>
${htmlContent}
</body>
</html>`;
}

/**
 * Stream AI analysis from OpenRouter Free Models API
 * @param {Object} fileData - File metadata (name, size, sha256, entropy, magicBytes, claimedExtension, strings, metadata)
 * @param {Object} streamResponse - SSE response object to write to
 */
async function streamForensicAnalysis(fileData, streamResponse) {
  let fullReport = '';

  const closeStream = (message) => {
    try {
      if (message) streamResponse.write(message);
      streamResponse.write(`data: [DONE]\n\n`);
      streamResponse.end();
    } catch (e) {
      console.error('Error closing SSE stream:', e);
      try { streamResponse.end(); } catch (_) {}
    }
  };

  if (!OPENROUTER_API_KEY) {
    streamResponse.write(`data: Error: OPENROUTER_API_KEY not configured. Please set it in your .env file.\n\n`);
    closeStream();
    return;
  }

  // Pre-compute summaries for v1 prompt
  const v1SigSummary = fileData.digitalSignature?.signed
    ? 'Signed by: ' + fileData.digitalSignature.publisher + ' | Issuer: ' + fileData.digitalSignature.issuer + ' | Trusted: ' + (fileData.digitalSignature.trusted ? 'YES' : 'NO')
    : fileData.digitalSignature?.status || 'Unsigned / No Certificate';

  const v1RiskBreakdown = fileData.riskScore?.breakdown
    ?.map(b => (b.delta >= 0 ? '+' : '') + b.delta + ' ' + b.signal + ': ' + b.reason)
    .join('\n') || 'N/A';

  const systemPrompt = `You are a forensic analyst explaining pre-computed risk findings to a security team.

IMPORTANT: A deterministic Hard Risk Scorer has already analysed this file and assigned a BINDING risk classification. You must NOT override, escalate, or invent a different risk level. Your job is to EXPLAIN the score in plain language, not second-guess it.

═══ HARD RISK SCORE (BINDING) ═══
Score: ${fileData.riskScore?.score ?? 'N/A'} → Classification: ${fileData.riskScore?.label ?? 'N/A'}
Breakdown:
${v1RiskBreakdown}

═══ FILE DETAILS ═══
- Name: ${fileData.name}
- Size: ${fileData.size} bytes
- SHA-256: ${fileData.sha256}
- Shannon Entropy: ${fileData.entropy} bits/byte
- Claimed Extension: ${fileData.claimedExtension || 'N/A'}
- Magic Bytes (hex): ${fileData.magicBytes || 'N/A'}
- Digital Signature: ${v1SigSummary}
- VirusTotal: Malicious: ${fileData.virusTotal?.malicious ?? 0}, Clean: ${fileData.virusTotal?.undetected ?? 0}
- PE Architecture: ${fileData.peAnalysis?.isPE ? fileData.peAnalysis.arch : 'Not a PE file'}

═══ YOUR TASK ═══
1. State the Hard Risk Score classification (${fileData.riskScore?.label ?? 'N/A'}) prominently at the top.
2. Walk through each scoring signal from the breakdown and explain what it means in human-readable forensic language.
3. For entropy: ${parseFloat(fileData.entropy) <= 4.0 ? 'This is LOW entropy — the file is NOT packed or encrypted. Do NOT describe it as packed.' : parseFloat(fileData.entropy) >= 7.2 ? 'This is high entropy — contextualise whether the file format normally has high entropy (zip, png, pdf = yes).' : 'This is moderate entropy — typical for most file types.'}
4. For IAT APIs: Only mention APIs as suspicious if the risk scorer flagged them. ShellExecuteW, Sleep, GetLastError, exception handlers, GetCurrentProcess, GetModuleHandle, GetProcAddress, LoadLibrary, ExitProcess, and CloseHandle are BENIGN housekeeping APIs present in virtually ALL Windows executables — do NOT flag them.
5. If the file is signed by a trusted vendor with 0 VT detections, explicitly state this is a safe, legitimate file.
6. End with the exact risk classification from the Hard Risk Score. Do NOT escalate beyond it.

Respond in a professional, investigative tone.`;

  try {
    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': SERVER_URL,
        'X-Title': 'ThreatLens Forensics'
      },
      body: JSON.stringify({
        model: 'openrouter/free',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: 'Begin your forensic analysis of this file.' }
        ],
        stream: true
      })
    });

    if (!response.ok) {
      let errorPayload;
      try {
        const errorText = await response.text();
        errorPayload = errorText ? JSON.parse(errorText) : { status: response.status };
      } catch (_) {
        errorPayload = { status: response.status };
      }
      console.error('OpenRouter API error:', response.status, errorPayload);
      streamResponse.write(`data: System Error: Agent Swarm upstream connection failed. Please try again later.\n\n`);
      closeStream();
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await reader.read();

        if (done) {
          const uploadsDir = join(__dirname, 'uploads');
          if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
          const reportFilename = `report-${fileData.sha256.slice(0, 12)}.html`;
          const reportPath = join(uploadsDir, reportFilename);
          try {
            const htmlReport = generateHTMLReport(fullReport);
            fs.writeFileSync(reportPath, htmlReport, 'utf8');
            const downloadUrl = `${SERVER_URL}/uploads/${reportFilename}`;
            streamResponse.write(`event: fileReady\ndata: ${JSON.stringify({ url: downloadUrl })}\n\n`);
          } catch (writeErr) {
            console.error('Report write error:', writeErr);
            streamResponse.write(`data: System Error: Could not save report file: ${writeErr.message}\n\n`);
          }
          closeStream();
          break;
        }

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const data = line.slice(6);
          if (data === '[DONE]') {
            const uploadsDir = join(__dirname, 'uploads');
            if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
            const reportFilename = `report-${fileData.sha256.slice(0, 12)}.html`;
            const reportPath = join(uploadsDir, reportFilename);
            try {
              const htmlReport = generateHTMLReport(fullReport);
              fs.writeFileSync(reportPath, htmlReport, 'utf8');
              const downloadUrl = `${SERVER_URL}/uploads/${reportFilename}`;
              streamResponse.write(`event: fileReady\ndata: ${JSON.stringify({ url: downloadUrl })}\n\n`);
            } catch (writeErr) {
              console.error('Report write error:', writeErr);
              streamResponse.write(`data: System Error: Could not save report file: ${writeErr.message}\n\n`);
            }
            closeStream();
            return;
          }
          try {
            const json = JSON.parse(data);
            const content = json.choices?.[0]?.delta?.content;
            if (content) {
              fullReport += content;
              streamResponse.write(`data: ${content}\n\n`);
            }
          } catch (_) {
            continue;
          }
        }
      }
    } catch (streamErr) {
      console.error('OpenRouter stream read error:', streamErr);
      streamResponse.write(`data: System Error: Agent Swarm upstream connection failed. Please try again later.\n\n`);
      closeStream();
    }
  } catch (error) {
    console.error('OpenRouter streaming error:', error);
    streamResponse.write(`data: System Error: Agent Swarm upstream connection failed. Please try again later.\n\n`);
    closeStream();
  }
}

// ─── V2 Multi-Agent Orchestration ───────────────────────────────────────────

/**
 * Call OpenRouter streaming API for a single agent.
 * Streams each token to the SSE response AND captures the full output.
 *
 * @param {number} agentId        Agent identifier (1, 2, 3)
 * @param {string} agentName      Human-readable agent name
 * @param {string} systemPrompt   System prompt for this agent
 * @param {string} userMessage    User message to kick off generation
 * @param {Object} sseRes         Express SSE response object
 * @returns {Promise<string>}     Full captured agent output
 */
async function runAgentStream(agentId, agentName, systemPrompt, userMessage, sseRes) {
  // Announce agent activation
  sseRes.write(`event: agentStart\ndata: ${JSON.stringify({ id: agentId, name: agentName })}\n\n`);

  let fullOutput = '';

  // Retry logic for rate-limited (429) responses — up to 3 attempts with exponential backoff
  const MAX_RETRIES = 3;
  let response;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': SERVER_URL,
          'X-Title': 'ThreatLens Forensics v2'
        },
        body: JSON.stringify({
          model: 'openrouter/free',
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userMessage }
          ],
          stream: true
        })
      });
    } catch (fetchErr) {
      if (attempt === MAX_RETRIES) {
        const errMsg = `Agent ${agentId} network error after ${MAX_RETRIES} attempts: ${fetchErr.message}`;
        sseRes.write(`data: ${errMsg}\n\n`);
        sseRes.write(`event: agentDone\ndata: ${JSON.stringify({ id: agentId })}\n\n`);
        return errMsg;
      }
      const backoff = attempt * 5000;
      sseRes.write(`data: [Agent ${agentId} network error, retrying in ${backoff / 1000}s...]\n\n`);
      await new Promise(r => setTimeout(r, backoff));
      continue;
    }

    // If rate-limited, wait and retry
    if (response.status === 429 && attempt < MAX_RETRIES) {
      const retryAfter = parseInt(response.headers.get('retry-after') || '0', 10);
      const backoff = Math.max((retryAfter || attempt * 5) * 1000, attempt * 5000);
      sseRes.write(`data: [Agent ${agentId} rate-limited (429), retrying in ${Math.round(backoff / 1000)}s...]\n\n`);
      await new Promise(r => setTimeout(r, backoff));
      continue;
    }

    // For non-429 errors or final 429 attempt, break out
    break;
  }

  try {
    if (!response.ok) {
      const errText = `Agent ${agentId} upstream error (HTTP ${response.status})`;
      sseRes.write(`data: ${errText}\n\n`);
      sseRes.write(`event: agentDone\ndata: ${JSON.stringify({ id: agentId })}\n\n`);
      return errText;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6);
        if (data === '[DONE]') continue;
        try {
          const json = JSON.parse(data);
          const content = json.choices?.[0]?.delta?.content;
          if (content) {
            fullOutput += content;
            sseRes.write(`data: ${content}\n\n`);
          }
        } catch (_) { continue; }
      }
    }
  } catch (err) {
    const errMsg = `Agent ${agentId} error: ${err.message}`;
    sseRes.write(`data: ${errMsg}\n\n`);
    fullOutput += errMsg;
  }

  sseRes.write(`event: agentDone\ndata: ${JSON.stringify({ id: agentId })}\n\n`);
  return fullOutput;
}

/**
 * V2 Deep Swarm Inspection — Three-agent orchestrated analysis.
 *
 * Agent 1 (Static Analyst)  → Entropy, Magic Bytes, Strings, EXIF, IAT
 * Agent 2 (Threat OSINT)    → VirusTotal, YARA-Lite matches
 * Agent 3 (Lead Investigator)→ Synthesises Agent 1+2 into a final forensic report
 */
async function streamDeepSwarmAnalysis(fileData, streamResponse) {
  const closeStream = (message) => {
    try {
      if (message) streamResponse.write(message);
      streamResponse.write(`data: [DONE]\n\n`);
      streamResponse.end();
    } catch (e) {
      console.error('Error closing SSE stream:', e);
      try { streamResponse.end(); } catch (_) {}
    }
  };

  if (!OPENROUTER_API_KEY) {
    streamResponse.write(`data: Error: OPENROUTER_API_KEY not configured.\n\n`);
    closeStream();
    return;
  }

  // Pre-compute digital signature summary for agent prompts
  const sigSummary = fileData.digitalSignature?.signed
    ? 'Signed by: ' + fileData.digitalSignature.publisher + ' | Issuer: ' + fileData.digitalSignature.issuer + ' | Trusted Vendor: ' + (fileData.digitalSignature.trusted ? 'YES' : 'NO')
    : fileData.digitalSignature?.status || 'Unsigned / No Certificate';

  // ── Agent 1: Static Analyst ─────────────────────────────────────────────
  const iatSummary = fileData.peAnalysis?.isPE && fileData.peAnalysis.imports.length > 0
    ? fileData.peAnalysis.imports
        .map(i => i.dll + ' [' + i.functions.slice(0, 8).join(', ') + (i.functions.length > 8 ? ' ... (' + i.functions.length + ' total)' : '') + ']')
        .join(' | ')
    : fileData.peAnalysis?.isPE ? 'PE but no imports' : 'N/A';

  const a1RiskBreakdown = fileData.riskScore?.breakdown
    ?.map(b => (b.delta >= 0 ? '+' : '') + b.delta + ' ' + b.signal + ': ' + b.reason)
    .join('\n') || 'N/A';

  const agent1Prompt = `You are Agent 1 — the Static Analyst in a multi-agent forensic swarm.

IMPORTANT: A deterministic Hard Risk Scorer has already classified this file. Your job is to EXPLAIN the static signals that contributed to the score. You must NOT override or escalate the pre-computed classification.

═══ HARD RISK SCORE (BINDING) ═══
Score: ${fileData.riskScore?.score ?? 'N/A'} → Classification: ${fileData.riskScore?.label ?? 'N/A'}
Breakdown:
${a1RiskBreakdown}

═══ FILE DETAILS ═══
- Name: ${fileData.name}
- Size: ${fileData.size} bytes
- SHA-256: ${fileData.sha256}
- Claimed Extension: ${fileData.claimedExtension || 'N/A'}
- Magic Bytes (hex): ${fileData.magicBytes || 'N/A'}
- Shannon Entropy: ${fileData.entropy} bits/byte
- Digital Signature: ${sigSummary}
- PE Architecture: ${fileData.peAnalysis?.isPE ? fileData.peAnalysis.arch : 'Not a PE file'}
- PE Import Table (IAT): ${iatSummary}

═══ YOUR TASK ═══
1. Shannon Entropy — contextualise for the file type. Only call entropy suspicious if HIGH_ENTROPY appears in the Hard Risk Score breakdown. If entropy did not score, report it as informational.
2. Magic bytes vs extension — report the comparison. If the risk scorer already scored this, just explain it.
3. Digital Signature — report signer and trust. Trusted vendor + 0 VT = safe.
4. IAT (PE only) — ONLY flag APIs that the risk scorer flagged. ShellExecuteW, Sleep, GetLastError, exception handlers, GetCurrentProcess, GetModuleHandle, GetProcAddress, LoadLibrary, ExitProcess, CloseHandle are BENIGN — do NOT flag them.
5. Do not invent IOCs, hashes, MITRE mappings, or malware behavior. Use only the file data and scoring breakdown above.
6. End with the SAME classification as the Hard Risk Score: ${fileData.riskScore?.label ?? 'N/A'}. Do NOT deviate.

Be concise and forensic.`;

  const agent1Output = await runAgentStream(
    1, 'Static Analyst', agent1Prompt,
    'Begin your static analysis of this file.', streamResponse
  );

  // ── Agent 2: Threat OSINT ───────────────────────────────────────────────
  const vtNote = fileData.virusTotal?.note ? ' (Note: ' + fileData.virusTotal.note + ')' : '';

  const yaraSummary = Array.isArray(fileData.yaraHits) && fileData.yaraHits.length > 0
    ? fileData.yaraHits
        .map(h => '[' + h.severity.toUpperCase() + '] ' + h.ruleName + ' (' + h.matchCount + ' hits): ' + h.description + '. Sample matches: ' + h.matches.slice(0, 5).map(m => '"' + m.pattern + '" @ offset ' + m.offset).join(', '))
        .join('\n')
    : 'No YARA-Lite rules triggered';

  const a2RiskBreakdown = fileData.riskScore?.breakdown
    ?.map(b => (b.delta >= 0 ? '+' : '') + b.delta + ' ' + b.signal + ': ' + b.reason)
    .join('\n') || 'N/A';

  const agent2Prompt = `You are Agent 2 — the Threat Intelligence & OSINT Analyst in a multi-agent forensic swarm.

IMPORTANT: A deterministic Hard Risk Scorer has already classified this file. Your job is to EXPLAIN the threat intelligence signals that contributed to the score. You must NOT override or escalate the pre-computed classification.

═══ HARD RISK SCORE (BINDING) ═══
Score: ${fileData.riskScore?.score ?? 'N/A'} → Classification: ${fileData.riskScore?.label ?? 'N/A'}
Breakdown:
${a2RiskBreakdown}

═══ THREAT INTELLIGENCE ═══
- SHA-256: ${fileData.sha256}
- VirusTotal: ${fileData.virusTotal?.malicious ?? 0} malicious / ${fileData.virusTotal?.undetected ?? 0} clean${vtNote}
- YARA-Lite Matches:
${yaraSummary}

═══ YOUR TASK ═══
1. VirusTotal — state the detection ratio and what it means. 0 malicious = clean. Do not speculate beyond the data.
2. YARA-Lite — for each triggered rule, explain what the detection means. If NO rules triggered, state the file passed automated screening. Do not infer PE import behavior from plain documentation text.
3. Do NOT re-analyse entropy, magic bytes, IAT, or digital signatures — Agent 1 handles those.
4. Do not invent hashes, IOCs, malware families, or MITRE techniques that are not present in the supplied findings.
5. End with the SAME classification as the Hard Risk Score: ${fileData.riskScore?.label ?? 'N/A'}. Do NOT deviate.

Be concise and actionable.`;

  const agent2Output = await runAgentStream(
    2, 'Threat OSINT', agent2Prompt,
    'Begin your threat intelligence analysis.', streamResponse
  );

  // --- Agent 3: Sandbox Analyst ---
  const sandboxSummary = fileData.sandbox?.detectedBehaviors?.length
    ? fileData.sandbox.detectedBehaviors.join(', ')
    : 'No simulated sandbox behaviors detected';
  const mitreSummary = fileData.sandbox?.mitreAttackTechniques?.length
    ? fileData.sandbox.mitreAttackTechniques.map(t => `${t.id} ${t.name} (${t.tactic})`).join('\n')
    : 'No MITRE ATT&CK techniques mapped';

  const agent3Prompt = `You are Agent 3 - the Sandbox Analyst in a multi-agent forensic swarm.

IMPORTANT: This is simulated static behavioral analysis, not live detonation. Explain only the deterministic import-to-behavior mapping. Do NOT override the Hard Risk Score.

HARD RISK SCORE (BINDING)
Score: ${fileData.riskScore?.score ?? 'N/A'} -> Classification: ${fileData.riskScore?.label ?? 'N/A'}

SIMULATED SANDBOX FINDINGS
- Note: ${fileData.sandbox?.sandboxNote || 'Simulated static behavioral analysis'}
- Detected behaviors: ${sandboxSummary}
- Suspicious imports: ${(fileData.sandbox?.suspiciousImports || []).join(', ') || 'None'}
- Behavior score: ${fileData.sandbox?.behaviorScore ?? 0}/100

MITRE ATT&CK
${mitreSummary}

Explain the behaviors and ATT&CK mapping concisely. End with the SAME classification as the Hard Risk Score: ${fileData.riskScore?.label ?? 'N/A'}.`;

  const agent3Output = await runAgentStream(
    3, 'Sandbox Analyst', agent3Prompt,
    'Begin your simulated sandbox and MITRE ATT&CK analysis.', streamResponse
  );

  // ── Agent 4: Lead Investigator (Synthesiser) ────────────────────────────
  const a3RiskBreakdown = fileData.riskScore?.breakdown
    ?.map(b => (b.delta >= 0 ? '+' : '') + b.delta + ' ' + b.signal + ': ' + b.reason)
    .join('\n') || 'N/A';

  const agent4Prompt = `You are Agent 4 - the Lead Forensic Investigator. You synthesise findings from your analyst team into a final forensic report.

CRITICAL: The Hard Risk Scorer has already classified this file with a BINDING score. You MUST use this exact classification as your final verdict. You may NOT override, escalate, or invent a different risk level.

═══ HARD RISK SCORE — BINDING FINAL VERDICT ═══
Score: ${fileData.riskScore?.score ?? 'N/A'} → Classification: ${fileData.riskScore?.label ?? 'N/A'}
Breakdown:
${a3RiskBreakdown}

═══ SUB-AGENT REPORTS ═══

--- AGENT 1 (Static Analyst) ---
${agent1Output}
--- END AGENT 1 ---

--- AGENT 2 (Threat OSINT) ---
${agent2Output}
--- END AGENT 2 ---

--- AGENT 3 (Sandbox Analyst) ---
${agent3Output}
--- END AGENT 3 ---

═══ YOUR TASK ═══
1. Cross-correlate — where do static and threat intel findings reinforce or contradict each other?
2. If either sub-agent assigned a classification different from ${fileData.riskScore?.label ?? 'N/A'}, explicitly CORRECT them and explain why the Hard Risk Score takes precedence.
3. FINAL VERDICT: State the classification as ${fileData.riskScore?.label ?? 'N/A'} (score ${fileData.riskScore?.score ?? 'N/A'}). Do NOT deviate.
4. Summarise key IOCs found, if any. If none, state clearly that no IOCs were found.
5. Do not invent IOCs, sample hashes, ATT&CK techniques, or recommendations that are unsupported by the deterministic findings.
6. Recommendations — containment steps for high-risk files, or "no action required" for safe files.

Format professionally with clear sections. This is the official forensic report.`;

  const agent4Output = await runAgentStream(
    4, 'Lead Investigator', agent4Prompt,
    'Synthesise the team findings and deliver your final forensic report.', streamResponse
  );

  // ── Save the combined report as HTML ───────────────────────────────────
  const fullReport = `# ThreatLens v3 - Sentinel Protocol Report\n\n## Agent 1: Static Analyst\n${agent1Output}\n\n---\n\n## Agent 2: Threat Intelligence & OSINT\n${agent2Output}\n\n---\n\n## Agent 3: Sandbox Analyst\n${agent3Output}\n\n---\n\n## Agent 4: Lead Investigator - Final Assessment\n${agent4Output}`;

  const uploadsDir = join(__dirname, 'uploads');
  if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
  const reportFilename = `report-${fileData.sha256.slice(0, 12)}.html`;
  const reportPath = join(uploadsDir, reportFilename);
  try {
    const htmlReport = generateHTMLReport(fullReport);
    fs.writeFileSync(reportPath, htmlReport, 'utf8');
    const downloadUrl = `${SERVER_URL}/uploads/${reportFilename}`;
    streamResponse.write(`event: fileReady\ndata: ${JSON.stringify({ url: downloadUrl })}\n\n`);
  } catch (writeErr) {
    console.error('Report write error:', writeErr);
    streamResponse.write(`data: System Error: Could not save report: ${writeErr.message}\n\n`);
  }

  closeStream();
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Sanitize filename — strip path components, keep only alphanumeric + dots/hyphens
    const safeName = path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, Date.now() + '-' + safeName);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10 MB max (demo-safe for public deployment)
    files: 1
  }
});

// ── Security Middleware ───────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // Allow inline scripts for SSE
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:5173', 'http://localhost:5174', 'http://localhost:3000'],
  methods: ['GET', 'POST'],
  credentials: false
}));

// Rate limit: 30 uploads per 15 minutes per IP
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many uploads. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

app.use(express.json({ limit: '1mb' }));

// Serve reports — only .html files, with nosniff + no-cache
app.use('/uploads', (req, res, next) => {
  // Block directory listing and non-report files
  const reqPath = decodeURIComponent(req.path);
  if (!reqPath.match(/^\/report-[a-f0-9]+\.html$/)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  next();
}, express.static(join(__dirname, 'uploads')));

// Global variable to hold our active SSE connection to the React GUI
let activeStreamResponse = null;

// The SSE Endpoint that React will connect to for live updates
app.get('/api/swarm-stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  activeStreamResponse = res;
});

function calculateFileHash(filePath) {
  return new Promise((resolve) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (data) => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

/**
 * Check a file hash against the VirusTotal v3 API.
 * Returns an object with malicious and undetected counts, or a safe default.
 * @param {string} sha256Hash
 * @returns {Promise<{ malicious: number, undetected: number, note?: string }>}
 */
async function checkVirusTotal(sha256Hash) {
  const safeDefault = {
    malicious: 0,
    undetected: 0,
    note: 'File not found in VirusTotal database or lookup unavailable'
  };

  if (!VIRUSTOTAL_API_KEY) {
    console.warn('VIRUSTOTAL_API_KEY not configured; skipping VirusTotal lookup.');
    return safeDefault;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const response = await fetch(`https://www.virustotal.com/api/v3/files/${sha256Hash}`, {
      method: 'GET',
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY
      },
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (response.status === 404) {
      return {
        malicious: 0,
        undetected: 0,
        note: 'File hash not found in VirusTotal database'
      };
    }

    if (!response.ok) {
      console.error('VirusTotal API error:', response.status);
      return { ...safeDefault, note: `VirusTotal API error (HTTP ${response.status})` };
    }

    const payload = await response.json();
    const stats = payload?.data?.attributes?.last_analysis_stats || {};
    const malicious = typeof stats.malicious === 'number' ? stats.malicious : 0;
    const undetected = typeof stats.undetected === 'number' ? stats.undetected : 0;

    return {
      malicious,
      undetected
    };
  } catch (error) {
    const reason = error.name === 'AbortError' || error.cause?.code === 'UND_ERR_CONNECT_TIMEOUT'
      ? 'Network timeout — could not reach VirusTotal (check internet/firewall)'
      : `VirusTotal lookup failed: ${error.message}`;
    console.warn('VT:', reason);
    return { ...safeDefault, note: reason };
  }
}

function getClaimedExtension(filename = '') {
  const parts = String(filename).split('.');
  if (parts.length < 2) return '';
  return parts.pop().toLowerCase();
}

function createAnalysisId() {
  return crypto.randomUUID();
}

function storeAnalysis(entry) {
  analysisStore.set(entry.analysisId, entry);
  return entry;
}

async function withTempBuffer(filename, content, callback) {
  const uploadsDir = join(__dirname, 'uploads');
  if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
  const safeName = path.basename(filename || 'sample.bin').replace(/[^a-zA-Z0-9._-]/g, '_');
  const tempPath = join(uploadsDir, `tmp-${Date.now()}-${crypto.randomUUID()}-${safeName}`);
  fs.writeFileSync(tempPath, content);
  try {
    return await callback(tempPath);
  } finally {
    try { fs.unlinkSync(tempPath); } catch (_) { /* best effort */ }
  }
}

async function analyzeFilePath({ filePath, originalName, size, source = 'file' }) {
  const sha256Hash = await calculateFileHash(filePath);
  const fileBuffer = fs.readFileSync(filePath);
  const entropyScore = calculateShannonEntropy(filePath);
  const magicBytes = extractMagicBytes(filePath);
  const extractedStrings = extractStrings(fileBuffer);
  const fileMetadata = await extractMetadata(filePath);
  const vtStats = await checkVirusTotal(sha256Hash);
  const peAnalysis = parseImportTable(fileBuffer);
  const yaraHits = scanWithYaraRules(fileBuffer);
  const digitalSignature = checkSignature(fileBuffer);
  const claimedExtension = getClaimedExtension(originalName);

  const [yaraify, malwareBazaar] = await Promise.all([
    scanWithYaraify(filePath),
    lookupMalwareBazaar(sha256Hash),
  ]);
  const sandbox = analyzeSandboxBehavior(peAnalysis);

  const riskScore = calculateRiskScore({
    claimedExtension,
    magicBytes,
    entropy: entropyScore,
    virusTotal: vtStats,
    yaraify,
    malwareBazaar,
    sandbox,
    digitalSignature,
    peAnalysis,
    yaraHits,
  });

  const analysisId = createAnalysisId();
  const timestamp = new Date().toISOString();
  const result = {
    analysisId,
    timestamp,
    name: originalName,
    size,
    sha256: sha256Hash,
    entropy: entropyScore,
    magicBytes,
    virusTotal: vtStats,
    yaraify,
    malwareBazaar,
    sandbox,
    extractedStrings,
    fileMetadata,
    peAnalysis,
    yaraHits,
    digitalSignature,
    riskScore,
    claimedExtension,
  };

  storeAnalysis({
    analysisId,
    timestamp,
    source,
    filename: originalName,
    identifier: originalName || sha256Hash,
    riskScore: riskScore.score,
    classification: riskScore.label,
    quarantined: false,
    reviewedByAdmin: false,
    result,
  });

  await sendHighRiskAlert({
    filename: originalName,
    score: riskScore.score,
    classification: riskScore.label,
    signals: riskScore.breakdown,
    analysisId,
  });

  return result;
}

async function analyzeBuffer({ filename, content, source = 'buffer' }) {
  return withTempBuffer(filename, content, (tempPath) => analyzeFilePath({
    filePath: tempPath,
    originalName: filename,
    size: content.length,
    source,
  }));
}

async function runAgentCompletion(fileData) {
  const riskBreakdown = fileData.riskScore?.breakdown
    ?.map((b) => `${b.delta >= 0 ? '+' : ''}${b.delta} ${b.signal}: ${b.reason}`)
    .join('\n') || 'N/A';

  if (!OPENROUTER_API_KEY) {
    return `AI summary unavailable because OPENROUTER_API_KEY is not configured. Hard Risk Score remains ${fileData.riskScore?.score}/100 (${fileData.riskScore?.label}).`;
  }

  try {
    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': SERVER_URL,
        'X-Title': 'ThreatLens Sentinel Protocol API'
      },
      body: JSON.stringify({
        model: 'openrouter/free',
        messages: [
          {
            role: 'system',
            content: `You explain deterministic malware triage results. Never override the Hard Risk Score. Final classification must stay ${fileData.riskScore?.label}.`
          },
          {
            role: 'user',
            content: `Summarize this analysis for an API client.\nScore: ${fileData.riskScore?.score}/100 (${fileData.riskScore?.label})\nSignals:\n${riskBreakdown}\nSHA-256: ${fileData.sha256}`
          }
        ],
        stream: false,
      }),
    });

    if (!response.ok) {
      return `AI summary unavailable due to upstream HTTP ${response.status}. Hard Risk Score: ${fileData.riskScore?.score}/100 (${fileData.riskScore?.label}).`;
    }

    const payload = await response.json();
    return payload?.choices?.[0]?.message?.content || `Hard Risk Score: ${fileData.riskScore?.score}/100 (${fileData.riskScore?.label}).`;
  } catch (error) {
    return `AI summary unavailable: ${error.message}. Hard Risk Score: ${fileData.riskScore?.score}/100 (${fileData.riskScore?.label}).`;
  }
}

function apiResponse({ result, input, agentSummary = '' }) {
  return {
    version: '3.0',
    analysisId: result.analysisId,
    timestamp: result.timestamp,
    input,
    credibilityScore: {
      score: result.riskScore.score,
      classification: result.riskScore.label,
      signals: result.riskScore.breakdown,
    },
    forensics: result,
    agentSummary,
    verdict: result.riskScore.label,
  };
}

// File upload endpoint
app.post('/upload', uploadLimiter, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const filePath = req.file.path;
  try {
    const result = await analyzeFilePath({
      filePath,
      originalName: req.file.originalname,
      size: req.file.size,
      source: 'upload',
    });

    // 1. Send immediate data back to GUI
    res.json({
      success: true,
      file: {
        analysisId: result.analysisId,
        timestamp: result.timestamp,
        name: result.name,
        size: result.size,
        sha256: result.sha256,
        entropy: result.entropy,
        magicBytes: result.magicBytes,
        virusTotal: result.virusTotal,
        yaraify: result.yaraify,
        malwareBazaar: result.malwareBazaar,
        sandbox: result.sandbox,
        extractedStrings: result.extractedStrings,
        fileMetadata: result.fileMetadata,
        peAnalysis: result.peAnalysis,
        yaraHits: result.yaraHits,
        digitalSignature: result.digitalSignature,
        riskScore: result.riskScore
      }
    });

    // 2. Stream real AI analysis from OpenRouter DeepSeek API
    if (activeStreamResponse) {
      const fileData = {
        name: result.name,
        size: result.size,
        sha256: result.sha256,
        entropy: result.entropy,
        magicBytes: result.magicBytes,
        claimedExtension: result.claimedExtension,
        virusTotal: result.virusTotal,
        yaraify: result.yaraify,
        malwareBazaar: result.malwareBazaar,
        sandbox: result.sandbox,
        strings: result.extractedStrings,
        metadata: result.fileMetadata,
        peAnalysis: result.peAnalysis,
        yaraHits: result.yaraHits,
        digitalSignature: result.digitalSignature,
        riskScore: result.riskScore
      };
      
      // Choose analysis mode
      const analysisMode = req.body?.mode || 'v1';
      const analysisFn = analysisMode === 'v2'
        ? streamDeepSwarmAnalysis
        : streamForensicAnalysis;

      analysisFn(fileData, activeStreamResponse).catch(error => {
        console.error('Forensic analysis streaming error:', error);
        if (activeStreamResponse) {
          try {
            activeStreamResponse.write(`data: System Error: Agent Swarm upstream connection failed. Please try again later.\n\n`);
            activeStreamResponse.write(`data: [DONE]\n\n`);
            activeStreamResponse.end();
          } catch (e) {
            console.error('Error closing SSE on analysis failure:', e);
          }
        }
      });
    }
  } catch (error) {
    console.error('Upload analysis error:', error);
    res.status(500).json({ error: 'File analysis failed' });
  } finally {
    // Clean up uploaded file after processing (don't keep user files on disk)
    try { fs.unlinkSync(filePath); } catch (_) { /* best effort */ }
  }
});

function requireAdminKey(req, res, next) {
  const key = req.get('X-Admin-Key');
  if (!key || key !== ADMIN_API_KEY) {
    return res.status(401).json({ error: 'Invalid admin key' });
  }
  next();
}

function requirePublicApiKey(req, res, next) {
  const key = req.get('X-API-Key');
  if (!PUBLIC_API_KEY || !key || key !== PUBLIC_API_KEY) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  next();
}

const apiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'API rate limit exceeded. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.get('X-API-Key') || ipKeyGenerator(req.ip),
});

app.post('/admin/login', (req, res) => {
  if (String(req.body?.pin || '') !== ADMIN_PIN) {
    return res.status(401).json({ ok: false, error: 'ACCESS DENIED' });
  }

  res.json({ ok: true, adminKey: ADMIN_API_KEY });
});

app.get('/admin/analyses', requireAdminKey, (req, res) => {
  const analyses = [...analysisStore.values()]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  res.json({ analyses });
});

app.get('/admin/stats', requireAdminKey, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const analyses = [...analysisStore.values()];
  const todayAnalyses = analyses.filter((entry) => entry.timestamp?.startsWith(today));
  const highRisk = todayAnalyses.filter((entry) => entry.classification === 'HIGH').length;
  const suspicious = todayAnalyses.filter((entry) => entry.classification === 'SUSPICIOUS').length;
  const clean = todayAnalyses.filter((entry) => entry.classification === 'LOW').length;
  const averageRiskScore = todayAnalyses.length
    ? Math.round(todayAnalyses.reduce((sum, entry) => sum + (entry.riskScore || 0), 0) / todayAnalyses.length)
    : 0;

  res.json({
    totalScansToday: todayAnalyses.length,
    highRisk,
    suspicious,
    clean,
    averageRiskScore,
  });
});

app.post('/admin/quarantine/:analysisId', requireAdminKey, (req, res) => {
  const entry = analysisStore.get(req.params.analysisId);
  if (!entry) return res.status(404).json({ error: 'Analysis not found' });

  entry.quarantined = true;
  entry.reviewedByAdmin = true;
  analysisStore.set(entry.analysisId, entry);
  res.json({ ok: true, analysisId: entry.analysisId, quarantined: true });
});

app.post('/analyze/email', uploadLimiter, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No email uploaded' });

  const filePath = req.file.path;
  try {
    const buffer = fs.readFileSync(filePath);
    if (!isEmlFile(req.file, buffer)) {
      return res.status(400).json({ error: 'Uploaded file is not an .eml email message' });
    }

    const parsedEmail = await parseEml(buffer, (attachment) => analyzeBuffer({
      filename: attachment.filename,
      content: attachment.content,
      source: 'email-attachment',
    }));

    const analysisId = createAnalysisId();
    const timestamp = new Date().toISOString();
    const classification = parsedEmail.overallRisk > 60
      ? 'HIGH'
      : parsedEmail.overallRisk >= 20 ? 'SUSPICIOUS' : 'LOW';

    storeAnalysis({
      analysisId,
      timestamp,
      source: 'email',
      filename: req.file.originalname,
      identifier: parsedEmail.emailMetadata.subject || req.file.originalname,
      riskScore: parsedEmail.overallRisk,
      classification,
      quarantined: false,
      reviewedByAdmin: false,
      result: parsedEmail,
    });

    await sendHighRiskAlert({
      filename: req.file.originalname,
      score: parsedEmail.overallRisk,
      classification,
      signals: [{ signal: 'EMAIL_AGGREGATED_RISK', delta: parsedEmail.overallRisk, reason: 'Aggregated attachment and URL risk' }],
      analysisId,
    });

    res.json({
      success: true,
      analysisId,
      timestamp,
      classification,
      email: parsedEmail,
    });
  } catch (error) {
    console.error('EML analysis error:', error);
    res.status(500).json({ error: 'Email analysis failed' });
  } finally {
    try { fs.unlinkSync(filePath); } catch (_) { /* best effort */ }
  }
});

app.post('/api/v1/scan', apiLimiter, requirePublicApiKey, upload.single('file'), async (req, res) => {
  let tempPathToDelete = null;

  try {
    let result;
    let input;

    if (req.file) {
      tempPathToDelete = req.file.path;
      result = await analyzeFilePath({
        filePath: req.file.path,
        originalName: req.file.originalname,
        size: req.file.size,
        source: 'api-file',
      });
      input = { type: 'file', identifier: req.file.originalname };
    } else if (req.body?.url) {
      const content = Buffer.from(String(req.body.url), 'utf8');
      result = await analyzeBuffer({ filename: 'submitted-url.txt', content, source: 'api-url' });
      input = { type: 'url', identifier: String(req.body.url) };
    } else if (req.body?.text) {
      const content = Buffer.from(String(req.body.text), 'utf8');
      result = await analyzeBuffer({ filename: 'submitted-text.txt', content, source: 'api-text' });
      input = { type: 'text', identifier: 'inline text' };
    } else {
      return res.status(400).json({ error: 'Submit multipart file or JSON { url } / { text }' });
    }

    const agentSummary = await runAgentCompletion(result);
    res.json(apiResponse({ result, input, agentSummary }));
  } catch (error) {
    console.error('Headless API scan error:', error);
    res.status(500).json({ error: 'Headless scan failed' });
  } finally {
    if (tempPathToDelete) {
      try { fs.unlinkSync(tempPathToDelete); } catch (_) { /* best effort */ }
    }
  }
});

app.listen(PORT, () => console.log(`ThreatLens API Server running on http://localhost:${PORT}`));
