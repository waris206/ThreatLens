import { useEffect, useState } from 'react';
import { ShieldX, X } from 'lucide-react';
import AdminStatsBar from './AdminStatsBar';
import ThreatFeed from './ThreatFeed';

const riskStyle = {
  HIGH: 'text-red-400',
  SUSPICIOUS: 'text-yellow-400',
  LOW: 'text-cyber-green',
};

const AdminDashboard = ({ adminKey, onClose }) => {
  const [analyses, setAnalyses] = useState([]);
  const [stats, setStats] = useState(null);

  const load = async () => {
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000';
    const headers = { 'X-Admin-Key': adminKey };
    const [analysesRes, statsRes] = await Promise.all([
      fetch(`${apiUrl}/admin/analyses`, { headers }),
      fetch(`${apiUrl}/admin/stats`, { headers }),
    ]);
    if (analysesRes.ok) setAnalyses((await analysesRes.json()).analyses || []);
    if (statsRes.ok) setStats(await statsRes.json());
  };

  useEffect(() => {
    load();
    const timer = setInterval(load, 10000);
    return () => clearInterval(timer);
  }, [adminKey]);

  const quarantine = async (analysisId) => {
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000';
    await fetch(`${apiUrl}/admin/quarantine/${analysisId}`, {
      method: 'POST',
      headers: { 'X-Admin-Key': adminKey },
    });
    load();
  };

  return (
    <div className="h-screen overflow-hidden p-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-xl font-bold tracking-widest text-cyber-green">SOC ADMIN DASHBOARD</h2>
          <p className="text-xs text-slate-500">Live analysis feed refreshes every 10 seconds</p>
        </div>
        <button onClick={onClose} className="p-2 rounded border border-zinc-700 text-slate-400 hover:text-slate-200" aria-label="Close SOC portal">
          <X className="w-4 h-4" />
        </button>
      </div>

      <AdminStatsBar stats={stats} />

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-4 mt-4 h-[calc(100vh-150px)]">
        <div className="border border-zinc-800 bg-slate-900 rounded overflow-hidden">
          <div className="max-h-full overflow-auto scrollbar-custom">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-slate-950 text-slate-400">
                <tr>
                  <th className="text-left p-3">Timestamp</th>
                  <th className="text-left p-3">Filename / URL</th>
                  <th className="text-left p-3">Risk</th>
                  <th className="text-left p-3">Classification</th>
                  <th className="text-left p-3">Analysis ID</th>
                  <th className="text-left p-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {analyses.map((entry) => (
                  <tr key={entry.analysisId} className="border-t border-zinc-800 hover:bg-slate-800/50">
                    <td className="p-3 text-slate-400">{new Date(entry.timestamp).toLocaleString()}</td>
                    <td className="p-3 text-slate-200 max-w-xs truncate">{entry.filename || entry.identifier}</td>
                    <td className={`p-3 font-bold ${riskStyle[entry.classification] || 'text-slate-300'}`}>{entry.riskScore}</td>
                    <td className={`p-3 font-bold ${riskStyle[entry.classification] || 'text-slate-300'}`}>{entry.classification}</td>
                    <td className="p-3 font-mono text-slate-500">{entry.analysisId}</td>
                    <td className="p-3">
                      <button
                        onClick={() => quarantine(entry.analysisId)}
                        disabled={entry.quarantined}
                        className="inline-flex items-center gap-1 rounded border border-red-400/30 px-2 py-1 text-red-300 disabled:text-slate-600 disabled:border-zinc-800"
                      >
                        <ShieldX className="w-3 h-3" />
                        {entry.quarantined ? 'Quarantined' : 'Quarantine'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <ThreatFeed analyses={analyses} />
      </div>
    </div>
  );
};

export default AdminDashboard;
