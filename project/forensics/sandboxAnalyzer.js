const behaviorMap = {
  PROCESS_INJECTION: [
    'VirtualAllocEx', 'WriteProcessMemory',
    'CreateRemoteThread', 'NtUnmapViewOfSection',
  ],
  PERSISTENCE: [
    'RegSetValueEx', 'RegCreateKeyEx',
    'CreateService', 'StartService',
  ],
  DEFENSE_EVASION: [
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
    'NtQueryInformationProcess', 'GetTickCount',
  ],
  CREDENTIAL_ACCESS: [
    'CryptAcquireContext', 'LsaOpenPolicy',
    'SamOpenDomain', 'CredEnumerate',
  ],
  NETWORK_COMMUNICATION: [
    'WSAStartup', 'connect', 'send', 'recv',
    'InternetOpenUrl', 'HttpSendRequest',
  ],
  FILE_SYSTEM: [
    'FindFirstFile', 'DeleteFile', 'MoveFile',
    'GetTempPath', 'CreateFile',
  ],
  RANSOMWARE_INDICATORS: [
    'CryptEncrypt', 'CryptGenKey',
    'GetLogicalDrives', 'FindFirstFile',
  ],
};

const attackMap = {
  PROCESS_INJECTION: { id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion' },
  PERSISTENCE: { id: 'T1547', name: 'Boot or Logon Autostart Execution', tactic: 'Persistence' },
  DEFENSE_EVASION: { id: 'T1497', name: 'Virtualization/Sandbox Evasion', tactic: 'Defense Evasion' },
  CREDENTIAL_ACCESS: { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access' },
  NETWORK_COMMUNICATION: { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
  RANSOMWARE_INDICATORS: { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
};

const behaviorWeights = {
  PROCESS_INJECTION: 35,
  PERSISTENCE: 25,
  DEFENSE_EVASION: 20,
  CREDENTIAL_ACCESS: 30,
  RANSOMWARE_INDICATORS: 40,
  NETWORK_COMMUNICATION: 15,
  FILE_SYSTEM: 5,
};

function normalizeImportName(name) {
  return String(name || '').replace(/[AW]$/, '');
}

/**
 * Perform simulated static behavioral analysis from a PE import table.
 *
 * This is not VM detonation. It maps imported APIs to behavior classes that a
 * dynamic sandbox would watch for, then exposes those behaviors with MITRE
 * ATT&CK context for analysts and downstream reports.
 *
 * @param {{ isPE: boolean, imports: Array<{ dll: string, functions: string[] }> }} peAnalysis
 * @returns {{
 *   detectedBehaviors: string[],
 *   mitreAttackTechniques: Array<{ id: string, name: string, tactic: string }>,
 *   suspiciousImports: string[],
 *   behaviorScore: number,
 *   sandboxNote: string
 * }}
 */
export function analyzeSandboxBehavior(peAnalysis = {}) {
  const detectedBehaviors = [];
  const suspiciousImports = new Set();

  if (peAnalysis?.isPE && Array.isArray(peAnalysis.imports)) {
    const importedFunctions = new Set();
    for (const entry of peAnalysis.imports) {
      for (const fn of entry.functions || []) {
        importedFunctions.add(fn);
        importedFunctions.add(normalizeImportName(fn));
      }
    }

    for (const [behavior, apis] of Object.entries(behaviorMap)) {
      const hits = apis.filter((api) => importedFunctions.has(api) || importedFunctions.has(normalizeImportName(api)));
      if (hits.length > 0) {
        detectedBehaviors.push(behavior);
        hits.forEach((api) => suspiciousImports.add(api));
      }
    }
  }

  const mitreAttackTechniques = detectedBehaviors
    .map((behavior) => attackMap[behavior])
    .filter(Boolean);

  const behaviorScore = Math.min(100, detectedBehaviors.reduce(
    (total, behavior) => total + (behaviorWeights[behavior] || 0),
    0,
  ));

  return {
    detectedBehaviors,
    mitreAttackTechniques,
    suspiciousImports: [...suspiciousImports],
    behaviorScore,
    sandboxNote: 'Simulated static behavioral analysis',
  };
}
