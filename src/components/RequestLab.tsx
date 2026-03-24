import React, { useState, useEffect } from 'react';
import { Play, Save, Copy, Terminal, FlaskConical, AlertCircle, Clock, Database, Sparkles, History, Plus } from 'lucide-react';
import Markdown from 'react-markdown';
import { GoogleGenAI } from '@google/genai';

export default function RequestLab({ initialRequest }: { initialRequest?: any }) {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('https://');
  const [headers, setHeaders] = useState('{\n  "Content-Type": "application/json"\n}');
  const [body, setBody] = useState('');
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [history, setHistory] = useState<any[]>([]);

  useEffect(() => {
    if (initialRequest) {
      setMethod(initialRequest.method || 'GET');
      setUrl(initialRequest.url || 'https://');
      setHeaders(initialRequest.headers ? JSON.stringify(initialRequest.headers, null, 2) : '{\n  "Content-Type": "application/json"\n}');
      setBody(initialRequest.body || '');
    }
  }, [initialRequest]);

  const fetchHistory = async () => {
    try {
      const res = await fetch('/api/history');
      const data = await res.json();
      setHistory(data);
    } catch (err) {
      console.error('Failed to fetch history');
    }
  };

  useEffect(() => {
    fetchHistory();
    const interval = setInterval(fetchHistory, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadHistoryItem = (item: any) => {
    setMethod(item.method);
    setUrl(item.url);
    try {
      setHeaders(JSON.stringify(JSON.parse(item.req_headers), null, 2));
    } catch {
      setHeaders(item.req_headers);
    }
    setBody(item.req_body || '');
    setResponse({
      status: item.status,
      headers: item.res_headers ? JSON.parse(item.res_headers) : {},
      body: item.res_body,
      duration: 0 // Not stored in history currently
    });
    setAiAnalysis(null);
  };

  const sendRequest = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch('/api/lab/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method,
          url,
          headers: JSON.parse(headers),
          body: body ? (method === 'GET' ? undefined : body) : undefined
        })
      });
      const data = await res.json();
      if (res.ok) {
        setResponse(data);
        setAiAnalysis(null);
        fetchHistory();
      } else {
        setError(data.error);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const analyzeResponse = async () => {
    if (!response) return;
    setAnalyzing(true);
    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
      const prompt = `Analyze this HTTP response for potential security vulnerabilities. 
      Focus on:
      1. Missing security headers
      2. Information disclosure
      3. Reflected input or XSS vectors
      4. Server errors indicating SQLi/RCE
      Return a concise, bulleted technical summary formatted in Markdown.
      
      Status: ${response.status}
      Headers: ${JSON.stringify(response.headers)}
      Body: ${typeof response.body === 'string' ? response.body.substring(0, 5000) : JSON.stringify(response.body).substring(0, 5000)}`;
      
      const aiResponse = await ai.models.generateContent({
        model: 'gemini-3-flash-preview',
        contents: prompt,
      });
      
      if (aiResponse.text) {
        setAiAnalysis(aiResponse.text);
      } else {
        setError("Failed to generate analysis.");
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setAnalyzing(false);
    }
  };

  const addH1Header = () => {
    try {
      const currentHeaders = JSON.parse(headers);
      setHeaders(JSON.stringify({ ...currentHeaders, "X-Hackerone": "argila" }, null, 2));
    } catch (e) {
      setHeaders(headers + '\n// Invalid JSON, please fix before adding header\n// "X-Hackerone": "argila"');
    }
  };

  return (
    <div className="h-full flex flex-col w-full bg-black/40 backdrop-blur-md relative overflow-hidden">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />
      <header className="p-6 border-b border-emerald-900/30 flex justify-between items-center bg-black/50 relative z-10 shadow-[0_4px_20px_rgba(0,0,0,0.3)]">
        <div className="absolute left-0 top-0 w-1 h-full bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <div className="pl-4">
          <h2 className="text-2xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
            <FlaskConical className="w-6 h-6 text-emerald-400" />
            Request Laboratory
          </h2>
          <p className="text-[10px] text-emerald-500/70 font-mono uppercase tracking-widest mt-1">Raw HTTP Manipulation & Replay</p>
        </div>
        <div className="flex gap-4">
          {response && (
            <button
              onClick={analyzeResponse}
              disabled={analyzing}
              className="px-6 py-2 text-xs font-mono uppercase tracking-widest flex items-center gap-2 border border-emerald-900/50 text-emerald-100 hover:bg-emerald-950/50 hover:text-emerald-400 hover:border-emerald-500/50 transition-all disabled:opacity-50 rounded-md relative overflow-hidden group"
            >
              {!analyzing && <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.05)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />}
              {analyzing ? <Clock className="w-4 h-4 animate-spin text-emerald-400 relative z-10" /> : <Sparkles className="w-4 h-4 text-emerald-400 relative z-10" />}
              <span className="relative z-10">AI Analyze</span>
            </button>
          )}
          <button
            onClick={sendRequest}
            disabled={loading}
            className="bg-emerald-500/10 border border-emerald-500/50 text-emerald-400 px-6 py-2 text-xs font-mono uppercase tracking-widest flex items-center gap-2 hover:bg-emerald-500/20 hover:shadow-[0_0_15px_rgba(16,185,129,0.4)] transition-all disabled:opacity-50 disabled:hover:shadow-none rounded-md shadow-[0_0_15px_rgba(16,185,129,0.1)] relative overflow-hidden group"
          >
            {!loading && <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.1)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />}
            {loading ? <Clock className="w-4 h-4 animate-spin relative z-10" /> : <Play className="w-4 h-4 relative z-10" />}
            <span className="relative z-10">Execute</span>
          </button>
        </div>
      </header>

      <div className="flex-1 grid grid-cols-12 overflow-hidden relative z-10">
        {/* History Sidebar */}
        <div className="col-span-2 border-r border-emerald-900/30 flex flex-col overflow-hidden bg-black/30 backdrop-blur-sm">
          <div className="p-3 bg-black/50 border-b border-emerald-900/30 text-[10px] font-mono text-emerald-500/70 uppercase tracking-wider flex items-center gap-2 shadow-[0_2px_10px_rgba(0,0,0,0.2)]">
            <History className="w-3 h-3" /> History
          </div>
          <div className="flex-1 overflow-y-auto scrollbar-hide">
            {history.map((item) => (
              <div 
                key={item.id} 
                onClick={() => loadHistoryItem(item)}
                className="p-3 border-b border-emerald-900/20 hover:bg-emerald-950/30 cursor-pointer transition-colors group relative overflow-hidden"
              >
                <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.02)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_3s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />
                <div className="flex justify-between items-center mb-1 relative z-10">
                  <span className={cn(
                    "text-[10px] font-mono px-1.5 py-0.5 rounded-sm border",
                    item.method === 'GET' ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400" :
                    item.method === 'POST' ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400" :
                    "bg-amber-500/10 border-amber-500/30 text-amber-400"
                  )}>
                    {item.method}
                  </span>
                  <span className={cn(
                    "text-[10px] font-mono",
                    item.status >= 200 && item.status < 300 ? "text-emerald-400 drop-shadow-[0_0_5px_rgba(16,185,129,0.5)]" : "text-red-400 drop-shadow-[0_0_5px_rgba(239,68,68,0.5)]"
                  )}>
                    {item.status}
                  </span>
                </div>
                <div className="text-xs font-mono text-emerald-100/70 group-hover:text-emerald-100 truncate w-full transition-colors relative z-10">{item.url}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Request Panel */}
        <div className="col-span-5 border-r border-emerald-900/30 flex flex-col overflow-hidden bg-black/40 backdrop-blur-md">
          <div className="p-3 bg-black/50 border-b border-emerald-900/30 flex gap-2 shadow-[0_2px_10px_rgba(0,0,0,0.2)]">
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="bg-black/50 border border-emerald-900/50 text-emerald-100 px-3 py-1.5 text-xs font-mono focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md transition-all"
            >
              {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'].map(m => (
                <option key={m} value={m} className="bg-emerald-950 text-emerald-100">{m}</option>
              ))}
            </select>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="flex-1 bg-black/50 border border-emerald-900/50 text-emerald-100 px-3 py-1.5 text-xs font-mono focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md transition-all placeholder:text-emerald-900/50"
            />
          </div>

          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="p-2 bg-black/30 text-[10px] font-mono text-emerald-500/70 uppercase tracking-wider border-b border-emerald-900/30 flex justify-between items-center">
              <span>Headers</span>
              <button onClick={addH1Header} className="text-emerald-400 hover:text-emerald-300 hover:drop-shadow-[0_0_5px_rgba(16,185,129,0.5)] flex items-center gap-1 transition-all">
                <Plus className="w-3 h-3" /> X-Hackerone
              </button>
            </div>
            <textarea
              value={headers}
              onChange={(e) => setHeaders(e.target.value)}
              className="flex-1 p-4 text-xs font-mono bg-transparent text-emerald-100/90 focus:outline-none resize-none scrollbar-hide"
            />
            
            <div className="p-2 bg-black/30 text-[10px] font-mono text-emerald-500/70 uppercase tracking-wider border-y border-emerald-900/30">Body</div>
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              className="h-1/3 p-4 text-xs font-mono bg-transparent text-emerald-100/90 focus:outline-none resize-none placeholder:text-emerald-900/50 scrollbar-hide"
              placeholder="Request body (JSON, raw, etc.)"
            />
          </div>
        </div>

        {/* Response Panel */}
        <div className="col-span-5 flex flex-col overflow-hidden bg-black/30 backdrop-blur-sm">
          {error && (
            <div className="p-4 bg-red-500/10 border-b border-red-500/30 text-red-400 flex items-center gap-2 text-xs font-mono shadow-[0_2px_10px_rgba(239,68,68,0.1)]">
              <AlertCircle className="w-4 h-4" />
              {error}
            </div>
          )}

          {!response && !error && (
            <div className="flex-1 flex flex-col items-center justify-center opacity-30">
              <FlaskConical className="w-16 h-16 mb-4 text-emerald-500/50 drop-shadow-[0_0_10px_rgba(16,185,129,0.2)]" />
              <p className="text-xs font-mono uppercase tracking-widest text-emerald-500/50">Awaiting execution...</p>
            </div>
          )}

          {response && (
            <div className="flex-1 flex flex-col overflow-hidden">
              <div className="p-3 bg-black/50 border-b border-emerald-900/30 flex justify-between items-center shadow-[0_2px_10px_rgba(0,0,0,0.2)]">
                <div className="flex gap-4 items-center">
                  <span className={cn(
                    "text-xs font-mono px-3 py-1 rounded-md border",
                    response.status >= 200 && response.status < 300 ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.2)]" : "bg-red-500/10 border-red-500/30 text-red-400 shadow-[0_0_10px_rgba(239,68,68,0.2)]"
                  )}>
                    {response.status}
                  </span>
                  <span className="text-[10px] font-mono text-emerald-500/70 uppercase tracking-widest">{response.duration}ms</span>
                </div>
                <button 
                  onClick={() => {
                    navigator.clipboard.writeText(JSON.stringify(response, null, 2));
                  }}
                  className="text-[10px] uppercase font-mono tracking-widest text-emerald-500/50 hover:text-emerald-400 hover:drop-shadow-[0_0_5px_rgba(16,185,129,0.5)] flex items-center gap-1 transition-all"
                >
                  <Copy className="w-3 h-3" /> Copy Raw
                </button>
              </div>

              <div className="flex-1 flex flex-col overflow-hidden">
                <div className="p-2 bg-black/30 text-[10px] font-mono text-emerald-500/70 uppercase tracking-wider border-b border-emerald-900/30">Response Headers</div>
                <div className="p-4 bg-black/40 text-[10px] font-mono overflow-auto max-h-48 border-b border-emerald-900/30 scrollbar-hide">
                  {Object.entries(response.headers).map(([k, v]) => (
                    <div key={k} className="flex gap-2">
                      <span className="text-emerald-500/50">{k}:</span>
                      <span className="text-emerald-400/80">{String(v)}</span>
                    </div>
                  ))}
                </div>

                <div className="p-2 bg-black/30 text-[10px] font-mono text-emerald-500/70 uppercase tracking-wider border-b border-emerald-900/30">Response Body</div>
                <pre className="flex-1 p-4 text-xs font-mono overflow-auto bg-black/40 text-emerald-100/90 scrollbar-hide">
                  {typeof response.body === 'object' 
                    ? JSON.stringify(response.body, null, 2) 
                    : response.body}
                </pre>
                
                {aiAnalysis && (
                  <div className="border-t border-emerald-900/50 bg-black/60 text-emerald-100 flex-shrink-0 max-h-64 flex flex-col relative">
                    <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/50 to-transparent" />
                    <div className="p-2 bg-emerald-500/10 text-[10px] font-mono uppercase tracking-wider border-b border-emerald-900/30 flex items-center gap-2 text-emerald-400 shadow-[0_2px_10px_rgba(16,185,129,0.1)]">
                      <Sparkles className="w-3 h-3 drop-shadow-[0_0_5px_currentColor]" /> AI Vulnerability Analysis
                    </div>
                    <div className="p-4 overflow-y-auto text-xs font-mono leading-relaxed prose prose-invert max-w-none prose-pre:bg-black/50 prose-pre:border prose-pre:border-emerald-900/30 prose-a:text-emerald-400 scrollbar-hide">
                      <Markdown>{aiAnalysis}</Markdown>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function cn(...inputs: any[]) {
  return inputs.filter(Boolean).join(' ');
}
