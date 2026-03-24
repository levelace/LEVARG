import React, { useState, useEffect } from 'react';
import { Binary, ArrowRightLeft, Copy, Trash2 } from 'lucide-react';

export default function Encoder({ initialText }: { initialText?: string }) {
  const [input, setInput] = useState(initialText || '');
  const [output, setOutput] = useState('');
  const [mode, setMode] = useState('b64encode');

  useEffect(() => {
    if (initialText) setInput(initialText);
  }, [initialText]);

  useEffect(() => {
    try {
      if (!input) {
        setOutput('');
        return;
      }
      switch (mode) {
        case 'b64encode': setOutput(btoa(input)); break;
        case 'b64decode': setOutput(atob(input)); break;
        case 'urlencode': setOutput(encodeURIComponent(input)); break;
        case 'urldecode': setOutput(decodeURIComponent(input)); break;
        case 'hexencode': setOutput(input.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')); break;
        case 'hexdecode': setOutput(input.match(/.{1,2}/g)?.map(byte => String.fromCharCode(parseInt(byte, 16))).join('') || ''); break;
        case 'htmlencode': setOutput(input.replace(/[\u00A0-\u9999<>\&]/g, i => '&#'+i.charCodeAt(0)+';')); break;
        case 'htmldecode': 
          const doc = new DOMParser().parseFromString(input, "text/html");
          setOutput(doc.documentElement.textContent || ''); 
          break;
        default: setOutput(input);
      }
    } catch (e) {
      setOutput('Error processing input');
    }
  }, [input, mode]);

  const modes = [
    { id: 'b64encode', label: 'Base64 Encode' },
    { id: 'b64decode', label: 'Base64 Decode' },
    { id: 'urlencode', label: 'URL Encode' },
    { id: 'urldecode', label: 'URL Decode' },
    { id: 'hexencode', label: 'Hex Encode' },
    { id: 'hexdecode', label: 'Hex Decode' },
    { id: 'htmlencode', label: 'HTML Encode' },
    { id: 'htmldecode', label: 'HTML Decode' },
  ];

  return (
    <div className="p-8 max-w-6xl mx-auto h-full flex flex-col w-full bg-black/40 backdrop-blur-md relative overflow-hidden">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />
      <header className="mb-8 relative z-10">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
          <Binary className="w-8 h-8 text-emerald-400" />
          Data Encoder
        </h2>
        <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">Transform and manipulate data strings</p>
      </header>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 min-h-0 relative z-10">
        <div className="lg:col-span-5 flex flex-col bg-black/50 border border-emerald-900/30 rounded-lg overflow-hidden shadow-[0_4px_20px_rgba(0,0,0,0.3)] group relative">
          <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.05)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />
          <div className="p-3 bg-black/50 border-b border-emerald-900/30 flex justify-between items-center relative z-10 shadow-[0_2px_10px_rgba(0,0,0,0.2)]">
            <span className="text-xs font-mono text-emerald-500/70 uppercase tracking-wider">Input</span>
            <button onClick={() => setInput('')} className="text-emerald-500/50 hover:text-red-400 transition-colors drop-shadow-[0_0_5px_rgba(239,68,68,0.3)]">
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="flex-1 p-4 bg-transparent text-sm font-mono text-emerald-100/90 focus:outline-none resize-none scrollbar-hide relative z-10 focus:bg-emerald-950/10 transition-colors"
            placeholder="Paste data here..."
          />
        </div>

        <div className="lg:col-span-2 flex flex-col gap-2 overflow-y-auto py-4 scrollbar-hide">
          {modes.map(m => (
            <button
              key={m.id}
              onClick={() => setMode(m.id)}
              className={`p-3 text-xs font-mono uppercase tracking-wider rounded-md border transition-all flex items-center justify-between relative overflow-hidden group ${
                mode === m.id 
                  ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.2)]' 
                  : 'bg-black/50 border-emerald-900/30 text-emerald-500/70 hover:border-emerald-500/50 hover:text-emerald-300 hover:bg-emerald-950/30'
              }`}
            >
              <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.1)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />
              <span className="relative z-10">{m.label}</span>
              {mode === m.id && <ArrowRightLeft className="w-3 h-3 relative z-10 drop-shadow-[0_0_5px_rgba(16,185,129,0.5)]" />}
            </button>
          ))}
        </div>

        <div className="lg:col-span-5 flex flex-col bg-black/50 border border-emerald-900/30 rounded-lg overflow-hidden shadow-[0_4px_20px_rgba(0,0,0,0.3)] relative group">
          <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.05)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />
          <div className="p-3 bg-black/50 border-b border-emerald-900/30 flex justify-between items-center relative z-10 shadow-[0_2px_10px_rgba(0,0,0,0.2)]">
            <span className="text-xs font-mono text-emerald-500/70 uppercase tracking-wider">Output</span>
            <button onClick={() => navigator.clipboard.writeText(output)} className="text-emerald-500/50 hover:text-emerald-400 transition-colors drop-shadow-[0_0_5px_rgba(16,185,129,0.3)]">
              <Copy className="w-4 h-4" />
            </button>
          </div>
          <textarea
            value={output}
            readOnly
            className="flex-1 p-4 bg-transparent text-sm font-mono text-emerald-400 focus:outline-none resize-none scrollbar-hide relative z-10 drop-shadow-[0_0_5px_rgba(16,185,129,0.2)]"
            placeholder="Result will appear here..."
          />
        </div>
      </div>
    </div>
  );
}
