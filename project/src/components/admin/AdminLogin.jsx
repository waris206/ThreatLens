import { useState } from 'react';
import { Lock, X } from 'lucide-react';

const AdminLogin = ({ onAuthenticated, onClose }) => {
  const [pin, setPin] = useState('');
  const [status, setStatus] = useState('idle');

  const submit = async (event) => {
    event.preventDefault();
    setStatus('checking');

    try {
      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000';
      const response = await fetch(`${apiUrl}/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin }),
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || 'ACCESS DENIED');
      setStatus('granted');
      setTimeout(() => onAuthenticated(payload.adminKey), 450);
    } catch (_) {
      setStatus('denied');
      setTimeout(() => setStatus('idle'), 900);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-6 font-mono">
      <button
        onClick={onClose}
        className="absolute top-5 right-5 p-2 rounded border border-zinc-700 text-slate-400 hover:text-slate-200 hover:border-zinc-500"
        aria-label="Close SOC portal"
      >
        <X className="w-4 h-4" />
      </button>

      <form onSubmit={submit} className="w-full max-w-sm border border-red-400/30 bg-black/60 rounded p-6 shadow-[0_0_30px_rgba(248,113,113,0.12)]">
        <div className="flex items-center gap-3 mb-6 text-red-400">
          <Lock className="w-5 h-5" />
          <div>
            <h2 className="text-lg font-bold tracking-widest">SOC PORTAL</h2>
            <p className="text-xs text-slate-500">Sentinel Protocol v3</p>
          </div>
        </div>

        <input
          value={pin}
          onChange={(event) => setPin(event.target.value.replace(/\D/g, '').slice(0, 6))}
          autoFocus
          inputMode="numeric"
          minLength={4}
          maxLength={6}
          className="w-full bg-slate-950 border border-zinc-700 rounded px-4 py-3 text-center text-2xl tracking-[0.4em] text-cyber-green outline-none focus:border-cyber-green"
          placeholder="PIN"
        />

        <button
          type="submit"
          className="mt-4 w-full rounded border border-red-400/40 bg-red-400/10 px-4 py-3 text-sm font-bold tracking-widest text-red-300 hover:bg-red-400/20"
        >
          AUTHENTICATE
        </button>

        <div className="mt-4 h-6 text-center text-xs font-bold tracking-widest">
          {status === 'checking' && <span className="text-slate-400 animate-pulse">CHECKING</span>}
          {status === 'granted' && <span className="text-cyber-green animate-pulse">ACCESS GRANTED</span>}
          {status === 'denied' && <span className="text-red-400 animate-pulse">ACCESS DENIED</span>}
        </div>
      </form>
    </div>
  );
};

export default AdminLogin;
