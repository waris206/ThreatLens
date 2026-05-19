import { FileIcon, Hash, Weight, CheckCircle, Copy, BarChart3, ShieldAlert, ShieldCheck, Bug, AlertTriangle, Box, Shield, ExternalLink, Mail, Radar } from 'lucide-react';
import { useState } from 'react';

const severityColor = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/30',
  high:     'text-orange-400 bg-orange-400/10 border-orange-400/30',
  medium:   'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  low:      'text-blue-400 bg-blue-400/10 border-blue-400/30',
  info:     'text-slate-400 bg-slate-400/10 border-slate-400/30',
};

const riskLabelStyle = {
  LOW:        'bg-emerald-400/15 text-emerald-400 border-emerald-400/40',
  SUSPICIOUS: 'bg-yellow-400/15 text-yellow-400 border-yellow-400/40',
  HIGH:       'bg-red-400/15 text-red-400 border-red-400/40',
};

const FileDetailsCard = ({ file }) => {
  const [copied, setCopied] = useState(false);
  const [showAllImports, setShowAllImports] = useState(false);

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const copyToClipboard = () => {
    if (!file.sha256) return;
    navigator.clipboard.writeText(file.sha256);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const peData = file.peAnalysis;
  const yaraData = file.yaraHits;
  const visibleImports = showAllImports
    ? (peData?.imports || [])
    : (peData?.imports || []).slice(0, 6);

  return (
    <div className="bg-slate-900/50 border border-zinc-800 rounded-lg p-6 space-y-6">
      <div className="flex items-start justify-between">
        <div className="flex items-start space-x-4">
          <div className="p-3 bg-slate-800 rounded-lg border border-zinc-700">
            <FileIcon className="w-8 h-8 text-cyber-blue" />
          </div>
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-slate-200 mb-1">
              {file.name}
            </h3>
            <div className="flex items-center space-x-4 text-sm text-slate-400">
              <div className="flex items-center space-x-1">
                <Weight className="w-4 h-4" />
                <span>{formatFileSize(file.size)}</span>
              </div>
              {file.entropy && (
                <div className="flex items-center space-x-1">
                  <BarChart3 className="w-4 h-4" />
                  <span>Entropy: {file.entropy}</span>
                </div>
              )}
              {peData?.isPE && (
                <div className="flex items-center space-x-1">
                  <Box className="w-4 h-4" />
                  <span>{peData.arch}</span>
                </div>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center space-x-2 text-xs text-cyber-green">
          <CheckCircle className="w-4 h-4" />
          <span>Verified</span>
        </div>
      </div>

      {file.emailAnalysis && (
        <div className="border border-cyber-blue/30 bg-cyber-blue/5 rounded p-4">
          <div className="flex items-center gap-2 mb-3 text-cyber-blue">
            <Mail className="w-4 h-4" />
            <span className="text-sm font-bold tracking-wider">EMAIL TRIAGE</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div className="bg-slate-950 border border-zinc-800 rounded p-3">
              <div className="text-slate-500 mb-1">Subject</div>
              <div className="text-slate-200">{file.emailAnalysis.emailMetadata?.subject || 'No subject'}</div>
            </div>
            <div className="bg-slate-950 border border-zinc-800 rounded p-3">
              <div className="text-slate-500 mb-1">From</div>
              <div className="text-slate-200">{file.emailAnalysis.emailMetadata?.from?.join(', ') || 'Unknown'}</div>
            </div>
            <div className="bg-slate-950 border border-zinc-800 rounded p-3">
              <div className="text-slate-500 mb-1">Attachments</div>
              <div className="text-slate-200">{file.emailAnalysis.attachmentResults?.length || 0} total, {file.emailAnalysis.suspiciousAttachments || 0} suspicious</div>
            </div>
            <div className="bg-slate-950 border border-zinc-800 rounded p-3">
              <div className="text-slate-500 mb-1">URLs</div>
              <div className="text-slate-200">{file.emailAnalysis.urlResults?.length || 0} total, {file.emailAnalysis.suspiciousUrls || 0} suspicious</div>
            </div>
          </div>
        </div>
      )}

      <div className="border-t border-zinc-800 pt-4 space-y-4">
        {/* ── Hard Risk Score ────────────────────────────────────── */}
        {file.riskScore && (
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <Shield className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">Hard Risk Score</span>
            </div>
            <div className="bg-slate-950 border border-zinc-800 rounded p-4">
              {file.malwareBazaar?.found && (
                <div className="mb-3 rounded border border-red-400/50 bg-red-400/15 px-3 py-2 text-xs font-bold tracking-wider text-red-300">
                  KNOWN MALWARE - MalwareBazaar confirmed this SHA-256 hash
                </div>
              )}
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <span className={`text-3xl font-bold tabular-nums ${
                    file.riskScore.label === 'LOW' ? 'text-emerald-400'
                    : file.riskScore.label === 'SUSPICIOUS' ? 'text-yellow-400'
                    : 'text-red-400'
                  }`}>{file.riskScore.score}</span>
                  <span className={`text-xs font-bold uppercase tracking-wider px-3 py-1 rounded-full border ${riskLabelStyle[file.riskScore.label] || riskLabelStyle.HIGH}`}>
                    {file.riskScore.label}
                  </span>
                </div>
                <span className="text-[10px] text-slate-500">Deterministic &bull; Pre-AI</span>
              </div>
              {Array.isArray(file.riskScore.breakdown) && file.riskScore.breakdown.length > 0 && (
                <div className="space-y-1 border-t border-zinc-800 pt-2">
                  {file.riskScore.breakdown.map((b, i) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <span className="text-slate-400">{b.signal}: <span className="text-slate-500">{b.reason}</span></span>
                      <span className={`font-mono font-semibold tabular-nums ${
                        b.delta > 0 ? 'text-red-400' : b.delta < 0 ? 'text-emerald-400' : 'text-slate-500'
                      }`}>{b.delta > 0 ? '+' : ''}{b.delta}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        <div>
          <div className="flex items-start justify-between mb-2">
            <div className="flex items-center space-x-2">
              <Hash className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">SHA-256 Hash</span>
            </div>
            {file.sha256 && (
              <div className="flex items-center gap-3">
                <button
                  onClick={copyToClipboard}
                  className="flex items-center space-x-1 text-xs text-slate-400 hover:text-cyber-green transition-colors"
                >
                  <Copy className="w-3 h-3" />
                  <span>{copied ? 'Copied!' : 'Copy SHA256'}</span>
                </button>
                <a
                  href={`https://bazaar.abuse.ch/browse.php?search=sha256%3A${file.sha256}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center space-x-1 text-xs text-slate-400 hover:text-red-300 transition-colors"
                >
                  <ExternalLink className="w-3 h-3" />
                  <span>Submit to MalwareBazaar</span>
                </a>
              </div>
            )}
          </div>
          <div className="bg-slate-950 border border-zinc-800 rounded p-3 overflow-x-auto">
            <code className="text-xs text-cyber-green font-mono break-all">
              {file.sha256}
              {!file.sha256 && 'N/A'}
            </code>
          </div>
        </div>
        
        {file.entropy && (
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <BarChart3 className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">Shannon Entropy</span>
            </div>
            <div className="bg-slate-950 border border-zinc-800 rounded p-3 mb-3">
              <code className="text-xs text-cyber-blue font-mono">
                {file.entropy} bits/byte
              </code>
            </div>
            {file.magicBytes && (
              <div>
                <div className="flex items-center space-x-2 mb-2">
                  <Hash className="w-4 h-4 text-slate-400" />
                  <span className="text-sm font-medium text-slate-300">Magic Bytes (Hex Signature)</span>
                </div>
                <div className="bg-slate-950 border border-zinc-800 rounded p-3">
                  <code className="text-xs text-cyber-blue font-mono">
                    {file.magicBytes}
                  </code>
                </div>
              </div>
            )}
          </div>
        )}
        
        {file.virusTotal && (
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <ShieldAlert className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">Threat Intelligence (VirusTotal)</span>
            </div>
            <div className="bg-slate-950 border border-zinc-800 rounded p-3">
              <code
                className={`text-xs font-mono ${
                  file.virusTotal.malicious > 0 ? 'text-red-400' : 'text-cyber-green'
                }`}
              >
                Malicious: {file.virusTotal.malicious ?? 0} / Clean: {file.virusTotal.undetected ?? 0}
              </code>
              {file.virusTotal.note && (
                <div className="text-xs text-slate-500 mt-1 font-mono">{file.virusTotal.note}</div>
              )}
            </div>
          </div>
        )}

        {(file.yaraify || file.malwareBazaar) && (
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <Radar className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">V3 Reputation Intelligence</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {file.yaraify && (
                <div className="bg-slate-950 border border-zinc-800 rounded p-3">
                  <div className="text-xs font-semibold text-cyber-blue mb-1">YARAify</div>
                  <div className={`text-xs font-mono ${file.yaraify.matchCount > 0 ? 'text-red-400' : 'text-cyber-green'}`}>
                    Matches: {file.yaraify.matchCount ?? 0}
                  </div>
                  {file.yaraify.malwareFamilies?.length > 0 && (
                    <div className="text-[11px] text-slate-400 mt-1">
                      Families: {file.yaraify.malwareFamilies.join(', ')}
                    </div>
                  )}
                  {file.yaraify.note && <div className="text-[11px] text-slate-500 mt-1">{file.yaraify.note}</div>}
                </div>
              )}
              {file.malwareBazaar && (
                <div className="bg-slate-950 border border-zinc-800 rounded p-3">
                  <div className="text-xs font-semibold text-red-300 mb-1">MalwareBazaar</div>
                  <div className={`text-xs font-mono ${file.malwareBazaar.found ? 'text-red-400' : 'text-cyber-green'}`}>
                    {file.malwareBazaar.found ? 'Known malware found' : 'Hash not found'}
                  </div>
                  {file.malwareBazaar.signature && (
                    <div className="text-[11px] text-slate-400 mt-1">Signature: {file.malwareBazaar.signature}</div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Digital Signature (Authenticode) ──────────────────── */}
        {file.digitalSignature && (
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <ShieldCheck className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">Digital Signature (Authenticode)</span>
            </div>
            <div className="bg-slate-950 border border-zinc-800 rounded p-3">
              {file.digitalSignature.signed ? (
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded-full border ${
                        file.digitalSignature.trusted
                          ? 'bg-emerald-400/10 text-emerald-400 border-emerald-400/30'
                          : 'bg-yellow-400/10 text-yellow-400 border-yellow-400/30'
                      }`}
                    >
                      {file.digitalSignature.trusted ? '✅' : '⚠️'}
                      {file.digitalSignature.trusted ? 'Signed' : 'Signed (Untrusted)'}: {file.digitalSignature.publisher}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 space-y-0.5">
                    <div>Issuer: <span className="text-slate-300">{file.digitalSignature.issuer}</span></div>
                    {file.digitalSignature.validFrom && (
                      <div>Valid: <span className="text-slate-300">{new Date(file.digitalSignature.validFrom).toLocaleDateString()} — {new Date(file.digitalSignature.validTo).toLocaleDateString()}</span></div>
                    )}
                    {file.digitalSignature.trusted && (
                      <div className="text-emerald-400 font-medium mt-1">🔒 Trust Anchor — Trusted vendor signature verified</div>
                    )}
                  </div>
                </div>
              ) : (
                <span
                  className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded-full border bg-slate-400/10 text-slate-400 border-slate-400/30"
                >
                  🔘 {file.digitalSignature.status}
                </span>
              )}
            </div>
          </div>
        )}

        {/* ── PE Import Address Table (IAT) ──────────────────────── */}
        {peData?.isPE && (
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <Box className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">
                PE Import Table (IAT)
                <span className="text-xs text-slate-500 ml-2">
                  {peData.imports.length} DLL{peData.imports.length !== 1 ? 's' : ''}
                </span>
              </span>
            </div>
            <div className="bg-slate-950 border border-zinc-800 rounded p-3 max-h-56 overflow-y-auto scrollbar-custom space-y-2">
              {peData.imports.length === 0 ? (
                <span className="text-xs text-slate-500">No imports found</span>
              ) : (
                <>
                  {visibleImports.map((imp, idx) => (
                    <div key={idx}>
                      <span className="text-xs font-semibold text-cyber-blue">{imp.dll}</span>
                      <span className="text-xs text-slate-500 ml-1">({imp.functions.length})</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {imp.functions.slice(0, 12).map((fn, fi) => (
                          <span
                            key={fi}
                            className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-zinc-700"
                          >
                            {fn}
                          </span>
                        ))}
                        {imp.functions.length > 12 && (
                          <span className="text-[10px] px-1.5 py-0.5 text-slate-500">
                            +{imp.functions.length - 12} more
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                  {peData.imports.length > 6 && (
                    <button
                      onClick={() => setShowAllImports(!showAllImports)}
                      className="text-xs text-cyber-blue hover:underline mt-1"
                    >
                      {showAllImports
                        ? 'Show less'
                        : `Show all ${peData.imports.length} DLLs`}
                    </button>
                  )}
                </>
              )}
            </div>
          </div>
        )}

        {/* Not a PE file notice */}
        {peData && !peData.isPE && (
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <Box className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">PE Analysis</span>
            </div>
            <div className="bg-slate-950 border border-zinc-800 rounded p-3">
              <span className="text-xs text-slate-500">{peData.error || 'Not a PE executable'}</span>
            </div>
          </div>
        )}

        {file.sandbox && (
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <Radar className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">Simulated Sandbox & MITRE ATT&CK</span>
            </div>
            <div className="bg-slate-950 border border-zinc-800 rounded p-3">
              <div className="flex flex-wrap gap-1 mb-3">
                {(file.sandbox.detectedBehaviors || []).length === 0 ? (
                  <span className="text-xs text-cyber-green">No mapped behaviors detected</span>
                ) : file.sandbox.detectedBehaviors.map((behavior) => (
                  <span key={behavior} className="text-[10px] px-2 py-1 rounded border border-red-400/30 bg-red-400/10 text-red-300">
                    {behavior}
                  </span>
                ))}
              </div>
              {(file.sandbox.mitreAttackTechniques || []).length > 0 && (
                <table className="w-full text-xs border-collapse">
                  <thead>
                    <tr className="text-slate-500 border-b border-zinc-800">
                      <th className="text-left py-2">Technique ID</th>
                      <th className="text-left py-2">Name</th>
                      <th className="text-left py-2">Tactic</th>
                    </tr>
                  </thead>
                  <tbody>
                    {file.sandbox.mitreAttackTechniques.map((technique) => (
                      <tr key={technique.id} className="border-b border-zinc-900">
                        <td className="py-2 font-mono text-red-300">{technique.id}</td>
                        <td className="py-2 text-slate-300">{technique.name}</td>
                        <td className="py-2 text-slate-400">{technique.tactic}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}

        {/* ── YARA-Lite Signature Alerts ─────────────────────────── */}
        {Array.isArray(yaraData) && (
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <Bug className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">
                YARA-Lite Signatures
                {yaraData.length > 0 && (
                  <span className="ml-2 text-xs text-red-400 font-bold animate-pulse">
                    {yaraData.length} ALERT{yaraData.length !== 1 ? 'S' : ''}
                  </span>
                )}
              </span>
            </div>
            {yaraData.length === 0 ? (
              <div className="bg-slate-950 border border-zinc-800 rounded p-3">
                <span className="text-xs text-cyber-green">No YARA-Lite rules triggered — passed automated signature screening</span>
              </div>
            ) : (
              <div className="space-y-2">
                {yaraData.map((hit, idx) => (
                  <div
                    key={idx}
                    className={`rounded border p-3 ${severityColor[hit.severity] || severityColor.info}`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4" />
                        <span className="text-sm font-semibold">{hit.ruleName}</span>
                      </div>
                      <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full border border-current">
                        {hit.severity}
                      </span>
                    </div>
                    <p className="text-xs opacity-80 mb-2">{hit.description}</p>
                    <div className="space-y-1">
                      {hit.matches.slice(0, 3).map((m, mi) => (
                        <div key={mi} className="text-[10px] font-mono bg-black/20 rounded px-2 py-1 break-all">
                          <span className="opacity-60">@{m.offset}</span>{' '}
                          <span>{m.snippet}</span>
                        </div>
                      ))}
                      {hit.matches.length > 3 && (
                        <span className="text-[10px] opacity-60">
                          +{hit.matches.length - 3} more match{hit.matches.length - 3 !== 1 ? 'es' : ''}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        <div>
          <div className="flex items-center space-x-2 mb-2">
            <span className="text-sm font-medium text-slate-300">EXIF / Metadata</span>
          </div>
          <div className="bg-slate-950 border border-zinc-800 rounded p-3 max-h-32 overflow-y-auto text-xs text-slate-300">
            {file.fileMetadata && file.fileMetadata.tags && Object.keys(file.fileMetadata.tags).length > 0 ? (
              <ul className="space-y-1">
                {Object.entries(file.fileMetadata.tags).map(([key, value]) => (
                  <li key={key}>
                    <span className="font-semibold text-slate-200">{key}:</span>{' '}
                    <span className="text-slate-400">{String(value)}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <span className="text-slate-500">No metadata found</span>
            )}
          </div>
        </div>

        <div>
          <div className="flex items-center space-x-2 mb-2">
            <span className="text-sm font-medium text-slate-300">Extracted Strings (Preview)</span>
          </div>
          <div className="bg-slate-950 border border-zinc-800 rounded p-3 max-h-40 overflow-y-auto">
            {Array.isArray(file.extractedStrings) && file.extractedStrings.length > 0 ? (
              <pre className="text-xs text-cyber-blue font-mono whitespace-pre-wrap break-words m-0">
                {file.extractedStrings.join('\n')}
              </pre>
            ) : (
              <span className="text-xs text-slate-500">No printable ASCII strings (6+ chars) extracted.</span>
            )}
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between text-xs">
        <span className="text-slate-500">Forensic integrity preserved</span>
        <span className="text-cyber-blue">Ready for analysis</span>
      </div>
    </div>
  );
};

export default FileDetailsCard;
