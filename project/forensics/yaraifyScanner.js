import fs from 'fs';
import crypto from 'crypto';

const YARAIFY_ENDPOINT = 'https://yaraify-api.abuse.ch/api/v1/';
const POLL_INTERVAL_MS = 3000;
const MAX_POLL_MS = 30000;

function unavailable(sha256, note = 'YARAify unavailable') {
  return {
    yaraMatches: [],
    matchCount: 0,
    knownMalware: false,
    malwareFamilies: [],
    sha256,
    note,
  };
}

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

function timeoutSignal(ms) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ms);
  return { controller, clear: () => clearTimeout(timeout) };
}

function inferFamilies(matches, clamavResults = []) {
  const candidates = [
    ...matches.flatMap((match) => [match.ruleName, match.description, ...(match.tags || [])]),
    ...clamavResults,
  ].filter(Boolean);
  const families = new Set();

  for (const raw of candidates) {
    const text = String(raw).toLowerCase();
    for (const family of ['ransomware', 'rat', 'stealer', 'loader', 'trojan', 'emotet', 'zegost', 'gh0strat']) {
      if (text.includes(family)) families.add(family === 'gh0strat' ? 'rat' : family);
    }
  }

  return [...families];
}

function parseMatchesFromData(data, sha256) {
  const tasks = Array.isArray(data?.tasks) ? data.tasks : [data].filter(Boolean);
  const rawStatic = [];
  const rawClam = [];

  for (const task of tasks) {
    if (Array.isArray(task.static_results)) rawStatic.push(...task.static_results);
    if (Array.isArray(task.clamav_results)) rawClam.push(...task.clamav_results);
    if (Array.isArray(task.unpack_results)) {
      for (const unpacked of task.unpack_results) {
        if (Array.isArray(unpacked.unpacked_yara_matches)) {
          rawStatic.push(...unpacked.unpacked_yara_matches);
        }
      }
    }
  }

  const yaraMatches = rawStatic
    .filter(Boolean)
    .map((match) => ({
      ruleName: match.rule_name || match.ruleName || 'Unknown YARA rule',
      author: match.author || null,
      description: match.description || null,
      malwareFamily: match.malware_family || match.malwareFamily || null,
      tags: Array.isArray(match.tags) ? match.tags : [],
    }));

  const malwareFamilies = [
    ...new Set([
      ...yaraMatches.map((match) => match.malwareFamily).filter(Boolean),
      ...inferFamilies(yaraMatches, rawClam),
    ]),
  ];

  return {
    yaraMatches,
    matchCount: yaraMatches.length,
    knownMalware: yaraMatches.length > 0 || rawClam.length > 0,
    malwareFamilies,
    sha256,
  };
}

async function postJson(query, authKey) {
  const { controller, clear } = timeoutSignal(15000);
  try {
    const response = await fetch(YARAIFY_ENDPOINT, {
      method: 'POST',
      headers: {
        'Auth-Key': authKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(query),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally {
    clear();
  }
}

async function submitFile(filePath, authKey) {
  const { controller, clear } = timeoutSignal(20000);
  try {
    const form = new FormData();
    const bytes = fs.readFileSync(filePath);
    form.append('file', new Blob([bytes]), filePath.split(/[\\/]/).pop() || 'sample.bin');
    form.append('json_data', new Blob([JSON.stringify({ clamav_scan: 1, unpack: 1, share_file: 0 })], {
      type: 'application/json',
    }));

    const response = await fetch(YARAIFY_ENDPOINT, {
      method: 'POST',
      headers: { 'Auth-Key': authKey },
      body: form,
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally {
    clear();
  }
}

async function pollTask(taskId, authKey, sha256) {
  const deadline = Date.now() + MAX_POLL_MS;

  while (Date.now() < deadline) {
    const payload = await postJson({ query: 'get_results', task_id: taskId }, authKey);
    const status = payload?.data?.task_status || payload?.task_status;

    if (payload?.query_status === 'ok' && status !== 'queued' && status !== 'processing') {
      return parseMatchesFromData(payload.data, sha256);
    }

    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }

  return unavailable(sha256, 'YARAify scan timed out');
}

/**
 * Scan a file through abuse.ch YARAify when configured.
 *
 * The current YARAify Community API requires an Auth-Key. If no key is
 * configured, the module returns a safe zero-impact fallback rather than
 * blocking local analysis.
 *
 * @param {string} filePath
 * @returns {Promise<{
 *   yaraMatches: Array<{ ruleName: string, author: string|null, description: string|null, malwareFamily: string|null, tags: string[] }>,
 *   matchCount: number,
 *   knownMalware: boolean,
 *   malwareFamilies: string[],
 *   sha256: string,
 *   note?: string
 * }>}
 */
export async function scanWithYaraify(filePath) {
  const sha256 = await sha256File(filePath);
  const authKey = process.env.YARAIFY_AUTH_KEY;

  if (!authKey) {
    return unavailable(sha256);
  }

  try {
    const lookup = await postJson({ query: 'lookup_hash', search_term: sha256 }, authKey);
    if (lookup?.query_status === 'ok' && lookup.data) {
      return parseMatchesFromData(lookup.data, sha256);
    }

    const submission = await submitFile(filePath, authKey);
    const taskId = submission?.task_id || submission?.data?.task_id;
    if (!taskId) {
      return unavailable(sha256, 'YARAify submission did not return a task ID');
    }

    return await pollTask(taskId, authKey, sha256);
  } catch (error) {
    const reason = error.name === 'AbortError'
      ? 'YARAify request timed out'
      : `YARAify unavailable: ${error.message}`;
    return unavailable(sha256, reason);
  }
}
