import React, { useEffect, useState } from 'react';
import { KeyRound } from 'lucide-react';

interface Session {
  id: string;
  scope_id: string;
  scope_domain?: string;
  name: string;
}

interface Props {
  value: string;
  onChange: (sessionId: string) => void;
  className?: string;
}

/**
 * Shared dropdown for picking an authenticated Session to inject into the
 * outgoing request. Used by Request Lab, Scanner, Stack Gap, Auto-Hunter and
 * Flow Runner so the same auth material from a single browser login flows
 * across every test surface.
 */
export default function SessionSelector({ value, onChange, className }: Props) {
  const [sessions, setSessions] = useState<Session[]>([]);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const res = await fetch('/api/sessions');
        if (!res.ok) return;
        const data: Session[] = await res.json();
        if (!cancelled) setSessions(data);
      } catch {
        /* network errors are expected during navigation */
      }
    };
    load();
    const i = setInterval(load, 5000);
    return () => { cancelled = true; clearInterval(i); };
  }, []);

  return (
    <div className={`flex items-center gap-2 ${className ?? ''}`}>
      <KeyRound className="w-4 h-4 text-emerald-400" />
      <label className="text-[10px] uppercase tracking-wider text-emerald-500/70 font-mono">
        Session
      </label>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="bg-black/60 border border-emerald-900/50 text-emerald-200 text-xs font-mono px-2 py-1 rounded focus:border-emerald-500 focus:outline-none"
      >
        <option value="">— anonymous —</option>
        {sessions.map(s => (
          <option key={s.id} value={s.id}>
            {s.name}{s.scope_domain ? ` (${s.scope_domain})` : ''}
          </option>
        ))}
      </select>
    </div>
  );
}
