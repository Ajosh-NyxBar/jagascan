import { ScanResult, ScanTarget, Vulnerability, ScanStatus, ScanType, DashboardStats } from '@/types';

// In-memory database for development - replace with real database in production
class MemoryDatabase {
  private scans: Map<string, ScanResult> = new Map();
  private targets: Map<string, ScanTarget> = new Map();
  private vulnerabilities: Map<string, Vulnerability[]> = new Map();

  // Scan operations
  async createScan(scan: ScanResult): Promise<ScanResult> {
    this.scans.set(scan.id, { ...scan });
    return scan;
  }

  async getScan(id: string): Promise<ScanResult | null> {
    return this.scans.get(id) || null;
  }

  async updateScan(id: string, updates: Partial<ScanResult>): Promise<ScanResult | null> {
    const existing = this.scans.get(id);
    if (!existing) return null;

    const updated = { ...existing, ...updates };
    this.scans.set(id, updated);
    return updated;
  }

  async deleteScan(id: string): Promise<boolean> {
    return this.scans.delete(id);
  }

  async getAllScans(
    filters?: {
      status?: ScanStatus;
      scanType?: ScanType;
      limit?: number;
      offset?: number;
    }
  ): Promise<ScanResult[]> {
    let results = Array.from(this.scans.values());

    // Apply filters
    if (filters?.status) {
      results = results.filter(scan => scan.status === filters.status);
    }
    
    if (filters?.scanType) {
      results = results.filter(scan => scan.scanType === filters.scanType);
    }

    // Sort by start time (newest first)
    results.sort((a, b) => b.startTime.getTime() - a.startTime.getTime());

    // Apply pagination
    if (filters?.offset !== undefined || filters?.limit !== undefined) {
      const offset = filters.offset || 0;
      const limit = filters.limit || 10;
      results = results.slice(offset, offset + limit);
    }

    return results;
  }

  // Target operations
  async createTarget(target: ScanTarget): Promise<ScanTarget> {
    this.targets.set(target.id, { ...target });
    return target;
  }

  async getTarget(id: string): Promise<ScanTarget | null> {
    return this.targets.get(id) || null;
  }

  async getTargetByUrl(url: string): Promise<ScanTarget | null> {
    for (const target of this.targets.values()) {
      if (target.url === url) return target;
    }
    return null;
  }

  // Vulnerability operations
  async addVulnerability(scanId: string, vulnerability: Vulnerability): Promise<void> {
    const existing = this.vulnerabilities.get(scanId) || [];
    existing.push(vulnerability);
    this.vulnerabilities.set(scanId, existing);
  }

  async getVulnerabilities(scanId: string): Promise<Vulnerability[]> {
    return this.vulnerabilities.get(scanId) || [];
  }

  // Dashboard stats
  async getDashboardStats(): Promise<DashboardStats> {
    const allScans = Array.from(this.scans.values());
    const allVulnerabilities = Array.from(this.vulnerabilities.values()).flat();

    return {
      totalScans: allScans.length,
      activeScans: allScans.filter(scan => 
        scan.status === ScanStatus.RUNNING || scan.status === ScanStatus.PENDING
      ).length,
      vulnerabilitiesFound: allVulnerabilities.length,
      criticalVulnerabilities: allVulnerabilities.filter(vuln => 
        vuln.severity === 'critical'
      ).length,
      recentScans: allScans
        .sort((a, b) => b.startTime.getTime() - a.startTime.getTime())
        .slice(0, 5)
    };
  }

  // Seed data for development
  async seedData(): Promise<void> {
    const sampleTarget: ScanTarget = {
      id: 'target_sample',
      url: 'https://example.com',
      domain: 'example.com',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    await this.createTarget(sampleTarget);

    const sampleScan: ScanResult = {
      id: 'scan_sample_1',
      targetId: sampleTarget.id,
      scanType: ScanType.WEB_VULNERABILITY,
      status: ScanStatus.COMPLETED,
      startTime: new Date(Date.now() - 3600000), // 1 hour ago
      endTime: new Date(Date.now() - 3000000), // 50 minutes ago
      vulnerabilities: [],
      metadata: {
        duration: 600000, // 10 minutes
        requestCount: 150,
        responseCount: 150,
        errorCount: 0,
        userAgent: 'JagaScan/1.0',
        scannerVersion: '1.0.0'
      }
    };

    await this.createScan(sampleScan);

    // Add sample vulnerabilities
    const sampleVulnerabilities: Vulnerability[] = [
      {
        id: 'vuln_1',
        type: 'sql_injection' as any,
        severity: 'high' as any,
        title: 'SQL Injection in Login Form',
        description: 'The login form is vulnerable to SQL injection attacks',
        solution: 'Use parameterized queries and input validation',
        evidence: 'Error message: "You have an error in your SQL syntax"',
        location: '/login',
        confidence: 95
      },
      {
        id: 'vuln_2',
        type: 'xss' as any,
        severity: 'medium' as any,
        title: 'Reflected XSS in Search',
        description: 'User input is reflected without proper sanitization',
        solution: 'Implement proper input validation and output encoding',
        evidence: 'Payload <script>alert(1)</script> was reflected',
        location: '/search',
        confidence: 87
      }
    ];

    for (const vuln of sampleVulnerabilities) {
      await this.addVulnerability(sampleScan.id, vuln);
    }

    sampleScan.vulnerabilities = sampleVulnerabilities;
    await this.updateScan(sampleScan.id, sampleScan);
  }
}

// Singleton instance
let dbInstance: MemoryDatabase | null = null;

export function getDatabase(): MemoryDatabase {
  if (!dbInstance) {
    dbInstance = new MemoryDatabase();
    // Seed data in development
    if (process.env.NODE_ENV === 'development') {
      dbInstance.seedData().catch(console.error);
    }
  }
  return dbInstance;
}

// Export types and functions for use in API routes
export type { ScanResult, ScanTarget, Vulnerability };
export { ScanStatus, ScanType } from '@/types';
