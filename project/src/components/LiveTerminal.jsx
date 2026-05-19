import { useEffect, useRef, useState } from 'react';
import { Terminal, Activity, Download, CheckCircle2 } from 'lucide-react';

const AGENT_COLORS = {
  1: { label: 'Agent 1 - Static Analyst', text: 'text-cyan-400', border: 'border-cyan-400/40', bg: 'bg-cyan-400/5', dot: 'bg-cyan-400' },
  2: { label: 'Agent 2 - Threat OSINT', text: 'text-amber-400', border: 'border-amber-400/40', bg: 'bg-amber-400/5', dot: 'bg-amber-400' },
  3: { label: 'Agent 3 - Sandbox Analyst', text: 'text-red-400', border: 'border-red-400/40', bg: 'bg-red-400/5', dot: 'bg-red-400' },
  4: { label: 'Agent 4 - Lead Investigator', text: 'text-emerald-400', border: 'border-emerald-400/40', bg: 'bg-emerald-400/5', dot: 'bg-emerald-400' },
};

const LiveTerminal = ({ isActive, analysisMode }) => {
  const [segments, setSegments] = useState([]);
  const [currentAgent, setCurrentAgent] = useState(null);
  const [reportDownloadUrl, setReportDownloadUrl] = useState(null);
  const terminalRef = useRef(null);

  useEffect(() => {
    if (isActive) {
      setSegments([]);
      setCurrentAgent(null);
      setReportDownloadUrl(null);
    }
  }, [isActive]);

  useEffect(() => {
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000';
    const eventSource = new EventSource(`${apiUrl}/api/swarm-stream`);

    eventSource.onmessage = (event) => {
      const data = event.data;
      if (!data || data === '[DONE]') return;

      if (analysisMode === 'v2') return;

      setSegments((prev) => {
        const updated = [...prev];
        if (updated.length === 0) {
          updated.push({ agentId: null, agentName: null, text: data, status: 'working' });
        } else {
          const last = updated[updated.length - 1];
          updated[updated.length - 1] = { ...last, text: last.text + data };
        }
        return updated;
      });
    };

    eventSource.addEventListener('agentStart', (event) => {
      try {
        const payload = JSON.parse(event.data);
        setCurrentAgent(payload);
        setSegments((prev) => [
          ...prev,
          { agentId: payload.id, agentName: payload.name, text: 'Working...', status: 'working' },
        ]);
      } catch (_) {}
    });

    eventSource.addEventListener('agentDone', (event) => {
      try {
        const payload = JSON.parse(event.data);
        setCurrentAgent((cur) => (cur?.id === payload.id ? null : cur));
        setSegments((prev) => prev.map((seg) => (
          seg.agentId === payload.id
            ? { ...seg, text: 'Done', status: 'done' }
            : seg
        )));
      } catch (_) {}
    });

    eventSource.addEventListener('fileReady', (event) => {
      try {
        const payload = JSON.parse(event.data);
        const url = payload?.url || event.data;
        if (url) setReportDownloadUrl(url);
      } catch {
        if (event.data) setReportDownloadUrl(event.data);
      }
    });

    eventSource.onerror = (error) => {
      console.error('SSE connection error:', error);
    };

    return () => eventSource.close();
  }, [analysisMode]);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [segments]);

  const hasContent = segments.length > 0;

  return (
    <div className="bg-slate-900 border border-zinc-800 rounded-lg flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800 bg-slate-950">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-cyber-green" />
          <span className="text-sm font-semibold text-slate-200">
            {analysisMode === 'v2' ? 'Deep Swarm Terminal' : 'Live Swarm Terminal'}
          </span>
        </div>
        <div className="flex items-center space-x-2">
          {currentAgent ? (
            <>
              <div className={`w-2 h-2 rounded-full animate-pulse ${AGENT_COLORS[currentAgent.id]?.dot || 'bg-cyber-green'}`} />
              <span className={`text-xs ${AGENT_COLORS[currentAgent.id]?.text || 'text-cyber-green'}`}>
                {currentAgent.name}
              </span>
            </>
          ) : isActive ? (
            <>
              <Activity className="w-4 h-4 text-cyber-green animate-pulse" />
              <span className="text-xs text-cyber-green">Active</span>
            </>
          ) : (
            <span className="text-xs text-slate-500">Idle</span>
          )}
        </div>
      </div>

      <div
        ref={terminalRef}
        className="flex-1 p-4 overflow-y-auto scrollbar-custom bg-slate-950/50 font-mono"
      >
        {!hasContent && !isActive && (
          <div className="flex flex-col items-center justify-center h-full text-slate-600">
            <Terminal className="w-12 h-12 mb-3 opacity-50" />
            <p className="text-sm">Awaiting file upload...</p>
            <p className="text-xs mt-1">
              {analysisMode === 'v2'
                ? '4 AI agents will activate upon analysis'
                : 'AI agent will activate upon analysis'}
            </p>
          </div>
        )}

        {segments.map((seg, idx) => {
          const colors = AGENT_COLORS[seg.agentId];
          if (!seg.text && !colors) return null;

          return (
            <div key={idx} className="mb-4">
              {colors && (
                <div className={`flex items-center gap-2 mb-2 px-3 py-1.5 rounded border ${colors.border} ${colors.bg}`}>
                  <div className={`w-2 h-2 rounded-full ${colors.dot}`} />
                  <span className={`text-xs font-bold tracking-wide uppercase ${colors.text}`}>
                    {colors.label}
                  </span>
                </div>
              )}
              {colors && analysisMode === 'v2' ? (
                <div className="flex items-center gap-2 pl-1 text-sm text-slate-300">
                  {seg.status === 'done' ? (
                    <CheckCircle2 className={`w-4 h-4 ${colors.text}`} />
                  ) : (
                    <Activity className={`w-4 h-4 animate-pulse ${colors.text}`} />
                  )}
                  <span>{seg.agentName} {seg.status === 'done' ? 'completed' : 'is working...'}</span>
                </div>
              ) : (
                <pre className="text-sm whitespace-pre-wrap font-sans break-words m-0 pl-1 text-slate-300">
                  {seg.text}
                </pre>
              )}
            </div>
          );
        })}
      </div>

      {reportDownloadUrl && (
        <div className="px-4 py-3 border-t border-zinc-800 bg-cyber-green/10">
          <a
            href={reportDownloadUrl}
            download
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-center gap-2 w-full py-3 px-4 rounded-lg bg-cyber-green text-slate-900 font-semibold text-sm shadow-lg shadow-cyber-green/20 hover:bg-cyber-green/90 transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <Download className="w-5 h-5" />
            Download Official Forensic Report (.html)
          </a>
        </div>
      )}

      <div className="px-4 py-2 border-t border-zinc-800 bg-slate-950">
        <div className="flex items-center space-x-2 text-xs text-slate-600">
          <div className="w-2 h-2 rounded-full bg-zinc-700"></div>
          <span>
            {currentAgent
              ? `${currentAgent.name} working...`
              : hasContent
                ? 'Analysis complete'
                : 'System ready'}
          </span>
        </div>
      </div>
    </div>
  );
};

export default LiveTerminal;
