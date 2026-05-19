import { simpleParser } from 'mailparser';
import path from 'path';

const URL_REGEX = /\bhttps?:\/\/[^\s<>"')]+/gi;
const SUSPICIOUS_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'click', 'quest', 'country']);
const SUSPICIOUS_HOST_HINTS = ['login', 'verify', 'update', 'secure', 'account', 'wallet', 'invoice'];

function normalizeAddressList(value) {
  return value?.value?.map((entry) => entry.address || entry.text).filter(Boolean) || [];
}

function extractUrls(text = '') {
  const matches = text.match(URL_REGEX) || [];
  return [...new Set(matches.map((url) => url.replace(/[.,;:!?]+$/, '')))];
}

function inspectDomain(url) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const labels = hostname.split('.');
    const tld = labels.at(-1) || '';
    const suspicious = (
      parsed.protocol !== 'https:' ||
      /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) ||
      SUSPICIOUS_TLDS.has(tld) ||
      SUSPICIOUS_HOST_HINTS.some((hint) => hostname.includes(hint)) ||
      hostname.length > 60
    );

    return {
      url,
      domainAge: null,
      suspicious,
      domain: hostname,
    };
  } catch (_) {
    return {
      url,
      domainAge: null,
      suspicious: true,
      domain: null,
    };
  }
}

/**
 * Check whether an upload is likely an RFC 822 email message.
 *
 * EML does not have a fixed magic byte sequence, so detection combines the
 * extension with common header signatures from the first bytes of the file.
 *
 * @param {{ originalname?: string }} file
 * @param {Buffer} buffer
 * @returns {boolean}
 */
export function isEmlFile(file, buffer) {
  const ext = path.extname(file?.originalname || '').toLowerCase();
  const head = Buffer.isBuffer(buffer) ? buffer.subarray(0, 2048).toString('utf8').toLowerCase() : '';
  return ext === '.eml' || (
    head.includes('from:') &&
    head.includes('to:') &&
    (head.includes('subject:') || head.includes('mime-version:') || head.includes('content-type:'))
  );
}

/**
 * Parse an EML file and run the existing file forensics pipeline over each
 * attachment through an injected callback.
 *
 * @param {Buffer} buffer
 * @param {(attachment: { filename: string, content: Buffer }) => Promise<object>} analyzeAttachment
 * @returns {Promise<{
 *   emailMetadata: { from: string[], to: string[], subject: string|null, date: string|null },
 *   attachmentResults: Array<{ filename: string, forensicsResult: object }>,
 *   urlResults: Array<{ url: string, domainAge: null, suspicious: boolean, domain: string|null }>,
 *   overallRisk: number,
 *   suspiciousAttachments: number,
 *   suspiciousUrls: number
 * }>}
 */
export async function parseEml(buffer, analyzeAttachment) {
  const parsed = await simpleParser(buffer);
  const textBody = [parsed.text || '', parsed.html || ''].join('\n');
  const urls = extractUrls(textBody);
  const urlResults = urls.map(inspectDomain);
  const attachmentResults = [];

  for (const attachment of parsed.attachments || []) {
    const filename = attachment.filename || 'attachment.bin';
    const content = Buffer.isBuffer(attachment.content)
      ? attachment.content
      : Buffer.from(attachment.content || '');
    const forensicsResult = await analyzeAttachment({ filename, content });
    attachmentResults.push({ filename, forensicsResult });
  }

  const suspiciousAttachments = attachmentResults.filter((entry) => {
    const score = entry.forensicsResult?.riskScore?.score ?? entry.forensicsResult?.credibilityScore?.score ?? 0;
    return score > 60;
  }).length;

  const suspiciousUrls = urlResults.filter((entry) => entry.suspicious).length;
  const highestAttachmentRisk = attachmentResults.reduce((max, entry) => {
    const score = entry.forensicsResult?.riskScore?.score ?? entry.forensicsResult?.credibilityScore?.score ?? 0;
    return Math.max(max, score);
  }, 0);
  const urlRisk = Math.min(40, suspiciousUrls * 10);

  return {
    emailMetadata: {
      from: normalizeAddressList(parsed.from),
      to: normalizeAddressList(parsed.to),
      subject: parsed.subject || null,
      date: parsed.date?.toISOString?.() || null,
    },
    attachmentResults,
    urlResults,
    overallRisk: Math.min(100, Math.max(highestAttachmentRisk, urlRisk)),
    suspiciousAttachments,
    suspiciousUrls,
  };
}
