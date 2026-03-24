export interface TargetMemory {
  host: string;
  tech: string[];
  identifiers: Record<string, string>; // e.g., client_id, app_id, pool_id
  interestingParams: string[];
  errorPatterns: string[];
  discoveredUsers: string[];
  findings: any[];
}

export class MemoryManager {
  private static memory: Record<string, TargetMemory> = {};

  static getMemory(jobId: string, host: string): TargetMemory {
    if (!this.memory[jobId]) {
      this.memory[jobId] = {
        host,
        tech: [],
        identifiers: {},
        interestingParams: [],
        errorPatterns: [],
        discoveredUsers: [],
        findings: []
      };
    }
    return this.memory[jobId];
  }

  static updateTech(jobId: string, host: string, tech: string[]) {
    const mem = this.getMemory(jobId, host);
    mem.tech = [...new Set([...mem.tech, ...tech])];
  }

  static addIdentifier(jobId: string, host: string, key: string, value: string) {
    const mem = this.getMemory(jobId, host);
    mem.identifiers[key] = value;
  }

  static addInterestingParam(jobId: string, host: string, param: string) {
    const mem = this.getMemory(jobId, host);
    if (!mem.interestingParams.includes(param)) {
      mem.interestingParams.push(param);
    }
  }

  static addErrorPattern(jobId: string, host: string, pattern: string) {
    const mem = this.getMemory(jobId, host);
    if (!mem.errorPatterns.includes(pattern)) {
      mem.errorPatterns.push(pattern);
    }
  }

  static addDiscoveredUser(jobId: string, host: string, user: string) {
    const mem = this.getMemory(jobId, host);
    if (!mem.discoveredUsers.includes(user)) {
      mem.discoveredUsers.push(user);
    }
  }

  static addFinding(jobId: string, host: string, finding: any) {
    const mem = this.getMemory(jobId, host);
    mem.findings.push(finding);
  }

  static clearMemory(jobId: string) {
    delete this.memory[jobId];
  }
}
