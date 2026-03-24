import React from 'react';
import { motion } from 'motion/react';
import { 
  Search, Fingerprint, Zap, ShieldAlert, FileText, 
  ArrowRight, CheckCircle2, AlertTriangle, Target, 
  Code, Bug, Share2, Info, Terminal
} from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface PhaseProps {
  number: number;
  title: string;
  icon: React.ReactNode;
  color: string;
  items: { label: string; description: string }[];
  delay?: number;
}

const Phase = ({ number, title, icon, color, items, delay = 0 }: PhaseProps) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay }}
      className={cn(
        "relative p-6 rounded-xl border bg-black/40 backdrop-blur-sm group transition-all duration-300 hover:shadow-lg",
        color === 'blue' && "border-blue-500/30 hover:shadow-blue-500/10",
        color === 'green' && "border-emerald-500/30 hover:shadow-emerald-500/10",
        color === 'orange' && "border-orange-500/30 hover:shadow-orange-500/10",
        color === 'pink' && "border-pink-500/30 hover:shadow-pink-500/10",
        color === 'gray' && "border-zinc-500/30 hover:shadow-zinc-500/10"
      )}
    >
      <div className="absolute -top-3 -left-3 w-8 h-8 rounded-full bg-zinc-900 border border-emerald-500/50 flex items-center justify-center text-[10px] font-bold font-mono text-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.3)]">
        0{number}
      </div>

      <div className="flex items-center gap-3 mb-6">
        <div className={cn(
          "p-2.5 rounded-lg bg-opacity-10",
          color === 'blue' && "bg-blue-500 text-blue-400",
          color === 'green' && "bg-emerald-500 text-emerald-400",
          color === 'orange' && "bg-orange-500 text-orange-400",
          color === 'pink' && "bg-pink-500 text-pink-400",
          color === 'gray' && "bg-zinc-500 text-zinc-400"
        )}>
          {icon}
        </div>
        <div>
          <h3 className="text-sm font-bold uppercase tracking-widest text-zinc-100">{title}</h3>
          <p className="text-[10px] text-zinc-500 font-mono uppercase">Phase {number}</p>
        </div>
      </div>

      <div className="space-y-4">
        {items.map((item, i) => (
          <div key={i} className="relative pl-4 border-l border-emerald-500/20 group/item">
            <div className="absolute left-[-1px] top-2 w-1 h-1 rounded-full bg-emerald-500/40 group-hover/item:bg-emerald-400 transition-colors" />
            <h4 className="text-[11px] font-bold text-zinc-300 group-hover/item:text-emerald-400 transition-colors">{item.label}</h4>
            <p className="text-[10px] text-zinc-500 leading-relaxed mt-0.5">{item.description}</p>
          </div>
        ))}
      </div>

      {/* Connector Arrow for Desktop */}
      <div className="hidden lg:block absolute -right-4 top-1/2 -translate-y-1/2 z-10 opacity-30 group-hover:opacity-100 transition-opacity">
        <ArrowRight className="w-4 h-4 text-emerald-500" />
      </div>
    </motion.div>
  );
};

export default function Methodology() {
  const phases = [
    {
      number: 1,
      title: "Reconnaissance",
      icon: <Search className="w-5 h-5" />,
      color: "blue",
      items: [
        { label: "Define Scope", description: "Read policy carefully: In-Scope vs. Out-of-Scope assets." },
        { label: "Identify Targets", description: "Passive Recon: WHOIS, ASN, Shodan, Censys." },
        { label: "Subdomain Discovery", description: "Amass, Subfinder, Assetfinder, Sublist3r." },
        { label: "Identify Technology", description: "Wappalyzer, BuiltWith, Nmap fingerprints." },
        { label: "Asset Fingerprinting", description: "Identify entry points & exposed interfaces." }
      ]
    },
    {
      number: 2,
      title: "Fingerprinting",
      icon: <Fingerprint className="w-5 h-5" />,
      color: "green",
      items: [
        { label: "Tech Stack Analysis", description: "Server: Apache, Nginx; DB: MySQL, Redis; Frameworks." },
        { label: "Identify Known Vulns", description: "CVEDB, ExploitDB, GitHub for public exploits." },
        { label: "Enumerate Subdomains", description: "Identify active vHosts & potential for Subdomain Takeover." },
        { label: "Configuration Analysis", description: "Scan for open ports, headers, TLS misconfigurations." }
      ]
    },
    {
      number: 3,
      title: "Discovery",
      icon: <Zap className="w-5 h-5" />,
      color: "orange",
      items: [
        { label: "Map the App Logic", description: "Crawl as user/guest; Analyze workflows & APIs." },
        { label: "Parameter Fuzzing", description: "Use Ffuf/Dirb/Wfuzz to find hidden endpoints & parameters." },
        { label: "Auth Testing", description: "Test for Broken Auth, MFA bypass, Session Hijacking." },
        { label: "Input Validation", description: "Test: SQLi, XSS, SSRF, RCE, IDOR, LFI/RFI." },
        { label: "Logic Flaw Identification", description: "Abuse business logic, e.g., shopping cart, payment flow." }
      ]
    },
    {
      number: 4,
      title: "Exploitation & PoC",
      icon: <ShieldAlert className="w-5 h-5" />,
      color: "pink",
      items: [
        { label: "Manual Exploitation", description: "Craft exploit; use Burp Suite for manipulation." },
        { label: "Document Impact", description: "Clearly demonstrate consequence, e.g., data loss or access." },
        { label: "Chaining Bugs", description: "Chain multiple low-severity issues into high/critical impact." },
        { label: "Confirm Reproducibility", description: "Ensure the vulnerability is easy to reproduce." }
      ]
    },
    {
      number: 5,
      title: "Reporting",
      icon: <FileText className="w-5 h-5" />,
      color: "gray",
      items: [
        { label: "Draft Clear Title", description: "Standard format: Issue Type on Target leading to Impact." },
        { label: "Write Summary", description: "Briefly explain the bug, why it matters, and who is affected." },
        { label: "Provide Step-by-Step PoC", description: "Include detailed steps, screenshots, and payloads." },
        { label: "Analyze Impact", description: "Explain the real-world business risk; CVSS score if required." },
        { label: "Offer Remediation", description: "Suggest mitigation strategies and secure coding practices." }
      ]
    }
  ];

  return (
    <div className="h-full flex flex-col bg-[#050505] p-6 overflow-y-auto scrollbar-hide">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-xl font-bold text-emerald-50 flex items-center gap-2">
            <Target className="w-6 h-6 text-emerald-400" />
            Impactful Bug Bounty Methodology
          </h2>
          <p className="text-xs text-zinc-500 mt-1 font-mono uppercase tracking-wider">Professional Security Research Framework</p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-[10px] font-mono text-emerald-300 uppercase tracking-tighter">Verified Workflow</span>
          </div>
        </div>
      </div>

      {/* Methodology Overview Card */}
      <div className="mb-8 p-6 rounded-xl bg-gradient-to-br from-emerald-950/20 to-black border border-emerald-500/20 relative overflow-hidden">
        <div className="absolute top-0 right-0 p-4 opacity-10">
          <Bug className="w-24 h-24 text-emerald-500" />
        </div>
        <div className="relative z-10 max-w-3xl">
          <h3 className="text-lg font-bold text-emerald-100 mb-2">The Sentinel Strategy</h3>
          <p className="text-sm text-zinc-400 leading-relaxed">
            This methodology is designed to maximize impact and professionalism in bug bounty hunting. 
            By following a structured approach from reconnaissance to reporting, you ensure that no asset 
            is overlooked and every vulnerability is documented with clear business impact.
          </p>
          <div className="flex items-center gap-6 mt-6">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]" />
              <span className="text-[10px] font-mono uppercase text-zinc-500">Passive</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.5)]" />
              <span className="text-[10px] font-mono uppercase text-zinc-500">Active</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-pink-500 shadow-[0_0_8px_rgba(236,72,153,0.5)]" />
              <span className="text-[10px] font-mono uppercase text-zinc-500">Exploitation</span>
            </div>
          </div>
        </div>
      </div>

      {/* Phases Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-6">
        {phases.map((phase, i) => (
          <Phase 
            key={phase.number} 
            {...phase} 
            delay={i * 0.1}
          />
        ))}
      </div>

      {/* Bottom Tips */}
      <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="p-4 rounded-lg bg-zinc-900/50 border border-zinc-800 flex gap-4">
          <div className="p-2 rounded bg-emerald-500/10 h-fit">
            <Info className="w-4 h-4 text-emerald-400" />
          </div>
          <div>
            <h4 className="text-xs font-bold text-zinc-200 mb-1 uppercase tracking-wider">Pro Tip: Chaining</h4>
            <p className="text-[10px] text-zinc-500 leading-relaxed">
              Never report a low-severity bug in isolation if it can be chained. An IDOR + CSRF can often lead to full account takeover.
            </p>
          </div>
        </div>
        <div className="p-4 rounded-lg bg-zinc-900/50 border border-zinc-800 flex gap-4">
          <div className="p-2 rounded bg-blue-500/10 h-fit">
            <Share2 className="w-4 h-4 text-blue-400" />
          </div>
          <div>
            <h4 className="text-xs font-bold text-zinc-200 mb-1 uppercase tracking-wider">Communication</h4>
            <p className="text-[10px] text-zinc-500 leading-relaxed">
              Be professional in triage. Clear communication with security teams builds trust and can lead to higher bounties.
            </p>
          </div>
        </div>
        <div className="p-4 rounded-lg bg-zinc-900/50 border border-zinc-800 flex gap-4">
          <div className="p-2 rounded bg-orange-500/10 h-fit">
            <Code className="w-4 h-4 text-orange-400" />
          </div>
          <div>
            <h4 className="text-xs font-bold text-zinc-200 mb-1 uppercase tracking-wider">Automation</h4>
            <p className="text-[10px] text-zinc-500 leading-relaxed">
              Automate the boring stuff (recon, basic fuzzing) so you can focus on complex business logic vulnerabilities.
            </p>
          </div>
        </div>
      </div>

      {/* Footer Branding */}
      <div className="mt-auto pt-12 pb-4 flex items-center justify-between border-t border-emerald-900/20">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-500/50" />
          <span className="text-[10px] font-mono text-zinc-600 uppercase tracking-[0.2em]">Sentinel Methodology v1.0</span>
        </div>
        <div className="text-[10px] font-mono text-emerald-500/30 uppercase tracking-widest italic">
          LEVELACE SENTINEL LLC — argila
        </div>
      </div>
    </div>
  );
}
