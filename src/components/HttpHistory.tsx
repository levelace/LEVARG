import React, { useState, useEffect } from 'react';
import { Search, Filter, RefreshCw, Clock, ArrowRight, ArrowDown, ArrowUp, Code2, FileJson } from 'lucide-react';

interface HistoryItem {
  id: string;
  method: string;
  url: string;
  req_headers: string;
  req_body: string;
  created_at: string;
  status: number;
  res_headers: string;
  res_body: string;
  res_id: string;
}

export default function HttpHistory() {
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [filteredHistory, setFilteredHistory] = useState<HistoryItem[]>([]);
  const [selectedItem, setSelectedItem] = useState<HistoryItem | null>(null);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [methodFilter, setMethodFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [activeTab, setActiveTab] = useState<'request' | 'response'>('request');

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/history');
      const data = await res.json();
      setHistory(data);
      applyFilters(data, searchTerm, methodFilter, statusFilter);
    } catch (err) {
      console.error('Failed to fetch history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
    const interval = setInterval(fetchHistory, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    applyFilters(history, searchTerm, methodFilter, statusFilter);
  }, [searchTerm, methodFilter, statusFilter, history]);

  const applyFilters = (data: HistoryItem[], search: string, method: string, status: string) => {
    let filtered = data;

    if (search) {
      const lowerSearch = search.toLowerCase();
      filtered = filtered.filter(item => 
        item.url.toLowerCase().includes(lowerSearch) || 
        (item.req_body && item.req_body.toLowerCase().includes(lowerSearch)) ||
        (item.res_body && item.res_body.toLowerCase().includes(lowerSearch))
      );
    }

    if (method !== 'ALL') {
      filtered = filtered.filter(item => item.method === method);
    }

    if (status !== 'ALL') {
      filtered = filtered.filter(item => {
        if (status === '2XX') return item.status >= 200 && item.status < 300;
        if (status === '3XX') return item.status >= 300 && item.status < 400;
        if (status === '4XX') return item.status >= 400 && item.status < 500;
        if (status === '5XX') return item.status >= 500 && item.status < 600;
        return true;
      });
    }

    setFilteredHistory(filtered);
  };

  const getMethodColor = (method: string) => {
    switch (method) {
      case 'GET': return 'text-cyan-400 drop-shadow-[0_0_5px_rgba(34,211,238,0.5)]';
      case 'POST': return 'text-emerald-400 drop-shadow-[0_0_5px_rgba(16,185,129,0.5)]';
      case 'PUT': return 'text-amber-400 drop-shadow-[0_0_5px_rgba(251,191,36,0.5)]';
      case 'DELETE': return 'text-red-400 drop-shadow-[0_0_5px_rgba(239,68,68,0.5)]';
      default: return 'text-zinc-400';
    }
  };

  const getStatusColor = (status: number) => {
    if (!status) return 'text-zinc-500';
    if (status >= 200 && status < 300) return 'text-emerald-400 drop-shadow-[0_0_5px_rgba(16,185,129,0.5)]';
    if (status >= 300 && status < 400) return 'text-cyan-400 drop-shadow-[0_0_5px_rgba(34,211,238,0.5)]';
    if (status >= 400 && status < 500) return 'text-amber-400 drop-shadow-[0_0_5px_rgba(251,191,36,0.5)]';
    if (status >= 500) return 'text-red-400 drop-shadow-[0_0_5px_rgba(239,68,68,0.5)]';
    return 'text-zinc-400';
  };

  const formatHeaders = (headersStr: string) => {
    try {
      const headers = JSON.parse(headersStr);
      return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n');
    } catch {
      return headersStr || 'No headers';
    }
  };

  const formatBody = (bodyStr: string) => {
    if (!bodyStr) return 'No body';
    try {
      const parsed = JSON.parse(bodyStr);
      return JSON.stringify(parsed, null, 2);
    } catch {
      return bodyStr;
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto h-full flex flex-col w-full bg-black/40 backdrop-blur-md relative overflow-hidden">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(16,185,129,0.05)_0%,transparent_50%)]" />
      <header className="mb-6 flex justify-between items-end relative z-10">
        <div className="absolute -left-4 top-1/2 -translate-y-1/2 w-1 h-12 bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,1)]" />
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-emerald-50 flex items-center gap-3 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
            <Clock className="w-8 h-8 text-emerald-400" />
            HTTP History
          </h2>
          <p className="text-xs text-emerald-500/70 font-mono mt-2 uppercase tracking-widest">Captured Requests and Responses</p>
        </div>
        <button 
          onClick={fetchHistory}
          className="p-2 bg-black/50 border border-emerald-900/50 rounded-md hover:bg-emerald-950/50 text-emerald-500/70 hover:text-emerald-400 hover:shadow-[0_0_10px_rgba(16,185,129,0.2)] transition-all"
          title="Refresh History"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </header>

      <div className="flex gap-4 mb-6 relative z-10">
        <div className="flex-1 relative group">
          <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.05)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity rounded-md" />
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500/50" />
          <input
            type="text"
            placeholder="Search URLs, request bodies, or response bodies..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-black/50 border border-emerald-900/50 text-emerald-100 pl-10 pr-4 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md transition-all placeholder:text-emerald-900/50 relative z-10"
          />
        </div>
        <div className="relative group">
          <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.05)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity rounded-md" />
          <Filter className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500/50" />
          <select
            value={methodFilter}
            onChange={(e) => setMethodFilter(e.target.value)}
            className="appearance-none bg-black/50 border border-emerald-900/50 text-emerald-100 pl-10 pr-8 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md transition-all relative z-10"
          >
            <option value="ALL" className="bg-emerald-950 text-emerald-100">All Methods</option>
            <option value="GET" className="bg-emerald-950 text-emerald-100">GET</option>
            <option value="POST" className="bg-emerald-950 text-emerald-100">POST</option>
            <option value="PUT" className="bg-emerald-950 text-emerald-100">PUT</option>
            <option value="DELETE" className="bg-emerald-950 text-emerald-100">DELETE</option>
            <option value="PATCH" className="bg-emerald-950 text-emerald-100">PATCH</option>
            <option value="OPTIONS" className="bg-emerald-950 text-emerald-100">OPTIONS</option>
          </select>
        </div>
        <div className="relative group">
          <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.05)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity rounded-md" />
          <Filter className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500/50" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="appearance-none bg-black/50 border border-emerald-900/50 text-emerald-100 pl-10 pr-8 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 rounded-md transition-all relative z-10"
          >
            <option value="ALL" className="bg-emerald-950 text-emerald-100">All Statuses</option>
            <option value="2XX" className="bg-emerald-950 text-emerald-100">2XX Success</option>
            <option value="3XX" className="bg-emerald-950 text-emerald-100">3XX Redirection</option>
            <option value="4XX" className="bg-emerald-950 text-emerald-100">4XX Client Error</option>
            <option value="5XX" className="bg-emerald-950 text-emerald-100">5XX Server Error</option>
          </select>
        </div>
      </div>

      <div className="flex-1 flex gap-6 min-h-0 relative z-10">
        {/* History List */}
        <div className="w-1/3 bg-black/40 backdrop-blur-md border border-emerald-900/30 rounded-lg flex flex-col overflow-hidden shadow-[0_4px_20px_rgba(0,0,0,0.3)]">
          <div className="p-3 bg-black/50 border-b border-emerald-900/30 flex justify-between items-center shadow-[0_2px_10px_rgba(0,0,0,0.2)]">
            <span className="text-[10px] uppercase font-mono tracking-widest text-emerald-500/70">Requests ({filteredHistory.length})</span>
          </div>
          <div className="flex-1 overflow-y-auto scrollbar-hide">
            {filteredHistory.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center opacity-50 p-4">
                <p className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/50 text-center">No requests found</p>
              </div>
            ) : (
              <ul className="divide-y divide-emerald-900/20">
                {filteredHistory.map((item) => (
                  <li key={item.id}>
                    <button
                      onClick={() => setSelectedItem(item)}
                      className={`w-full text-left p-3 hover:bg-emerald-950/30 transition-colors relative overflow-hidden group ${selectedItem?.id === item.id ? 'bg-emerald-950/50 border-l-2 border-l-emerald-500' : 'border-l-2 border-l-transparent'}`}
                    >
                      {selectedItem?.id !== item.id && <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.02)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_3s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />}
                      <div className="flex justify-between items-start mb-1 relative z-10">
                        <span className={`text-xs font-bold font-mono ${getMethodColor(item.method)}`}>{item.method}</span>
                        <span className={`text-xs font-mono ${getStatusColor(item.status)}`}>{item.status || '---'}</span>
                      </div>
                      <div className="text-xs font-mono text-emerald-100/70 group-hover:text-emerald-100 truncate mb-2 transition-colors relative z-10" title={item.url}>{item.url}</div>
                      <div className="text-[10px] font-mono text-emerald-500/50 relative z-10">{new Date(item.created_at).toLocaleString()}</div>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* Details Pane */}
        <div className="w-2/3 bg-black/40 backdrop-blur-md border border-emerald-900/30 rounded-lg flex flex-col overflow-hidden shadow-[0_4px_20px_rgba(0,0,0,0.3)]">
          {!selectedItem ? (
            <div className="h-full flex flex-col items-center justify-center opacity-30">
              <Code2 className="w-12 h-12 mb-4 text-emerald-500/50 drop-shadow-[0_0_10px_rgba(16,185,129,0.2)]" />
              <p className="text-xs font-mono uppercase tracking-widest text-emerald-500/50">Select a request to view details</p>
            </div>
          ) : (
            <>
              <div className="p-4 bg-black/50 border-b border-emerald-900/30 shadow-[0_2px_10px_rgba(0,0,0,0.2)]">
                <div className="flex items-center gap-3 mb-2">
                  <span className={`text-sm font-bold font-mono ${getMethodColor(selectedItem.method)}`}>{selectedItem.method}</span>
                  <span className="text-sm font-mono text-emerald-100 break-all">{selectedItem.url}</span>
                </div>
                <div className="flex items-center gap-4 text-xs font-mono">
                  <span className={`flex items-center gap-1 ${getStatusColor(selectedItem.status)}`}>
                    <div className={`w-2 h-2 rounded-full ${selectedItem.status >= 200 && selectedItem.status < 300 ? 'bg-emerald-400 shadow-[0_0_5px_rgba(16,185,129,0.8)]' : selectedItem.status >= 400 ? 'bg-red-400 shadow-[0_0_5px_rgba(239,68,68,0.8)]' : 'bg-amber-400 shadow-[0_0_5px_rgba(251,191,36,0.8)]'}`} />
                    Status: {selectedItem.status || 'Pending/Failed'}
                  </span>
                  <span className="text-emerald-500/50 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {new Date(selectedItem.created_at).toLocaleString()}
                  </span>
                </div>
              </div>

              <div className="flex border-b border-emerald-900/30 bg-black/30">
                <button
                  onClick={() => setActiveTab('request')}
                  className={`flex-1 py-2.5 text-xs font-mono uppercase tracking-widest flex items-center justify-center gap-2 transition-all relative overflow-hidden group ${activeTab === 'request' ? 'text-emerald-400 border-b-2 border-emerald-400 bg-emerald-500/10 shadow-[inset_0_-2px_10px_rgba(16,185,129,0.1)]' : 'text-emerald-500/50 hover:text-emerald-300 hover:bg-emerald-950/30'}`}
                >
                  {activeTab !== 'request' && <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.02)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />}
                  <ArrowUp className="w-3.5 h-3.5 relative z-10" /> <span className="relative z-10">Request</span>
                </button>
                <button
                  onClick={() => setActiveTab('response')}
                  className={`flex-1 py-2.5 text-xs font-mono uppercase tracking-widest flex items-center justify-center gap-2 transition-all relative overflow-hidden group ${activeTab === 'response' ? 'text-emerald-400 border-b-2 border-emerald-400 bg-emerald-500/10 shadow-[inset_0_-2px_10px_rgba(16,185,129,0.1)]' : 'text-emerald-500/50 hover:text-emerald-300 hover:bg-emerald-950/30'}`}
                >
                  {activeTab !== 'response' && <div className="absolute inset-0 bg-[linear-gradient(45deg,transparent_25%,rgba(16,185,129,0.02)_50%,transparent_75%)] bg-[length:250%_250%,100%_100%] animate-[shimmer_2s_infinite_linear] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity" />}
                  <ArrowDown className="w-3.5 h-3.5 relative z-10" /> <span className="relative z-10">Response</span>
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-hide">
                {activeTab === 'request' ? (
                  <>
                    <div>
                      <h4 className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/70 mb-2">Headers</h4>
                      <pre className="text-xs font-mono text-emerald-100/90 bg-black/50 p-3 rounded-md border border-emerald-900/30 overflow-x-auto whitespace-pre-wrap scrollbar-hide shadow-[inset_0_2px_10px_rgba(0,0,0,0.2)]">
                        {formatHeaders(selectedItem.req_headers)}
                      </pre>
                    </div>
                    <div>
                      <h4 className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/70 mb-2">Body</h4>
                      <pre className="text-xs font-mono text-emerald-100/90 bg-black/50 p-3 rounded-md border border-emerald-900/30 overflow-x-auto whitespace-pre-wrap min-h-[100px] scrollbar-hide shadow-[inset_0_2px_10px_rgba(0,0,0,0.2)]">
                        {formatBody(selectedItem.req_body)}
                      </pre>
                    </div>
                  </>
                ) : (
                  <>
                    <div>
                      <h4 className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/70 mb-2">Headers</h4>
                      <pre className="text-xs font-mono text-emerald-100/90 bg-black/50 p-3 rounded-md border border-emerald-900/30 overflow-x-auto whitespace-pre-wrap scrollbar-hide shadow-[inset_0_2px_10px_rgba(0,0,0,0.2)]">
                        {formatHeaders(selectedItem.res_headers)}
                      </pre>
                    </div>
                    <div>
                      <h4 className="text-[10px] font-mono uppercase tracking-widest text-emerald-500/70 mb-2">Body</h4>
                      <pre className="text-xs font-mono text-emerald-100/90 bg-black/50 p-3 rounded-md border border-emerald-900/30 overflow-x-auto whitespace-pre-wrap min-h-[100px] scrollbar-hide shadow-[inset_0_2px_10px_rgba(0,0,0,0.2)]">
                        {formatBody(selectedItem.res_body)}
                      </pre>
                    </div>
                  </>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
