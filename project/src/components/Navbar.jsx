import { Shield, Bug, Radar } from 'lucide-react';

const Navbar = ({ onOpenAdmin }) => {
  return (
    <nav className="bg-slate-900 border-b border-zinc-800 px-6 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="relative">
            <Shield className="w-8 h-8 text-cyber-green" strokeWidth={2} />
            <Bug className="w-4 h-4 text-cyber-blue absolute -bottom-1 -right-1" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-cyber-green cyber-glow tracking-wider">
              ThreatLens
            </h1>
            <p className="text-xs text-slate-400 tracking-wide">
              AI-Driven Malware Triage & Deep Swarm Inspection
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-6">
          <button
            onClick={onOpenAdmin}
            className="inline-flex items-center gap-2 rounded border border-red-400/30 bg-red-400/10 px-3 py-2 text-xs font-bold tracking-wider text-red-300 hover:bg-red-400/20"
          >
            <Radar className="w-3.5 h-3.5" />
            SOC PORTAL
          </button>
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-cyber-green rounded-full animate-pulse"></div>
            <span className="text-xs text-slate-400">Swarm Active</span>
          </div>
          <div className="text-xs text-slate-500">
            v3.0.0
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
