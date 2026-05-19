const Stat = ({ label, value, tone = 'text-slate-200' }) => (
  <div className="border border-zinc-800 bg-slate-950 rounded p-3">
    <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
    <div className={`text-2xl font-bold tabular-nums ${tone}`}>{value}</div>
  </div>
);

const AdminStatsBar = ({ stats }) => (
  <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
    <Stat label="Scans Today" value={stats?.totalScansToday ?? 0} />
    <Stat label="High Risk" value={stats?.highRisk ?? 0} tone="text-red-400" />
    <Stat label="Suspicious" value={stats?.suspicious ?? 0} tone="text-yellow-400" />
    <Stat label="Clean" value={stats?.clean ?? 0} tone="text-cyber-green" />
    <Stat label="Average Risk" value={stats?.averageRiskScore ?? 0} tone="text-cyber-blue" />
  </div>
);

export default AdminStatsBar;
