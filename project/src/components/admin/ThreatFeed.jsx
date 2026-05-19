const ThreatFeed = ({ analyses = [] }) => {
  const highRisk = analyses
    .filter((entry) => entry.classification === 'HIGH')
    .slice(0, 10);

  return (
    <aside className="border border-zinc-800 bg-slate-950 rounded p-4 min-h-80">
      <h3 className="text-sm font-bold text-red-400 tracking-wider mb-3">HIGH RISK FEED</h3>
      <div className="space-y-3">
        {highRisk.length === 0 ? (
          <div className="text-xs text-slate-600">No high risk detections</div>
        ) : highRisk.map((entry) => {
          const recent = Date.now() - new Date(entry.timestamp).getTime() < 5 * 60 * 1000;
          return (
            <div key={entry.analysisId} className="border border-red-400/20 bg-red-400/5 rounded p-3">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full bg-red-400 ${recent ? 'animate-pulse' : ''}`} />
                <span className="text-xs font-semibold text-slate-200 truncate">{entry.filename || entry.identifier}</span>
              </div>
              <div className="mt-2 flex items-center justify-between text-[11px]">
                <span className="text-red-400 font-bold">{entry.riskScore}/100</span>
                <span className="text-slate-500">{new Date(entry.timestamp).toLocaleTimeString()}</span>
              </div>
            </div>
          );
        })}
      </div>
    </aside>
  );
};

export default ThreatFeed;
