import { ZAPClient, ZAPConfig, ZAPAlert, ZAPScanStatus } from './zapClient';
import { scannerService } from './scannerService';
import { ScanStatus, Vulnerability, VulnerabilityType, Severity } from '@/types/index';

export interface ZAPScanOptions {
  spiderMaxDepth?: number;
  spiderMaxChildren?: number;
  activeScanPolicy?: string;
  contextName?: string;
  enablePassiveScan?: boolean;
  enableActiveScan?: boolean;
}

export interface ZAPScanProgress {
  phase: 'spider' | 'active' | 'completed' | 'failed';
  spiderProgress: number;
  activeScanProgress: number;
  overallProgress: number;
  currentTask: string;
  alertsFound: number;
}

export class ZAPIntegrationService {
  private zapClient: ZAPClient;
  private config: ZAPConfig;

  constructor(config: ZAPConfig) {
    this.config = config;
    this.zapClient = new ZAPClient(config);
  }

  /**
   * Test ZAP connectivity and setup
   */
  async testConnection(): Promise<{ connected: boolean; version?: string; error?: string }> {
    try {
      const connected = await this.zapClient.testConnection();
      if (connected) {
        const version = await this.zapClient.getVersion();
        return { connected: true, version };
      } else {
        return { connected: false, error: 'Unable to connect to ZAP' };
      }
    } catch (error) {
      return { 
        connected: false, 
        error: error instanceof Error ? error.message : 'Unknown connection error'
      };
    }
  }

  /**
   * Start comprehensive ZAP scan
   */
  async startScan(
    targetUrl: string, 
    options: ZAPScanOptions = {}
  ): Promise<{ 
    success: boolean; 
    scanId: string; 
    spiderScanId?: string; 
    activeScanId?: string;
    error?: string;
  }> {
    try {
      console.log('🕷️ Starting ZAP scan for:', targetUrl);

      // Generate unique scan ID for tracking
      const scanId = `zap-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      // Access the URL first to add it to ZAP's session
      await this.zapClient.accessUrl(targetUrl);
      
      // Start spider scan first
      let spiderScanId: string | undefined;
      if (options.enablePassiveScan !== false) {
        spiderScanId = await this.zapClient.startSpider(
          targetUrl, 
          options.spiderMaxChildren || 10
        );
        console.log('🕷️ Spider scan started with ID:', spiderScanId);
      }

      // Start monitoring progress (don't await, run in background)
      this.monitorZAPScanProgress(scanId, spiderScanId, targetUrl, options).catch(error => {
        console.error('❌ Error monitoring ZAP scan:', error);
      });

      // Active scan will be started after spider completes
      return {
        success: true,
        scanId,
        spiderScanId,
        activeScanId: undefined
      };

    } catch (error) {
      console.error('❌ Failed to start ZAP scan:', error);
      return {
        success: false,
        scanId: '',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Get current scan progress
   */
  async getScanProgress(
    scanId: string,
    spiderScanId?: string,
    activeScanId?: string
  ): Promise<ZAPScanProgress> {
    try {
      let spiderProgress = 100;
      let activeScanProgress = 0;
      let phase: 'spider' | 'active' | 'completed' | 'failed' = 'completed';
      let currentTask = 'Scan completed';

      // Check spider progress
      if (spiderScanId) {
        const spiderStatus = await this.zapClient.getSpiderStatus(spiderScanId);
        spiderProgress = spiderStatus.progress;
        
        if (spiderProgress < 100) {
          phase = 'spider';
          currentTask = `Spider crawling website... (${spiderProgress}%)`;
        }
      }

      // Check active scan progress
      if (activeScanId) {
        const activeStatus = await this.zapClient.getActiveScanStatus(activeScanId);
        activeScanProgress = activeStatus.progress;
        
        if (activeScanProgress < 100) {
          phase = 'active';
          currentTask = `Active security testing... (${activeScanProgress}%)`;
        }
      }

      // Start active scan if spider is complete and active scan hasn't started
      if (spiderProgress === 100 && !activeScanId && phase !== 'completed') {
        // This would need to be handled by the calling code
        phase = 'active';
        currentTask = 'Starting active security scan...';
      }

      // Calculate overall progress
      const overallProgress = spiderScanId && activeScanId 
        ? Math.round((spiderProgress + activeScanProgress) / 2)
        : spiderScanId 
          ? spiderProgress 
          : activeScanProgress;

      // Get current alerts count
      const alerts = await this.zapClient.getAlerts();
      const alertsFound = alerts.length;

      if (overallProgress === 100) {
        phase = 'completed';
        currentTask = `Scan completed - ${alertsFound} security issues found`;
      }

      return {
        phase,
        spiderProgress,
        activeScanProgress,
        overallProgress,
        currentTask,
        alertsFound
      };

    } catch (error) {
      console.error('❌ Error getting scan progress:', error);
      return {
        phase: 'failed',
        spiderProgress: 0,
        activeScanProgress: 0,
        overallProgress: 0,
        currentTask: 'Failed to get scan progress',
        alertsFound: 0
      };
    }
  }

  /**
   * Start active scan (usually called after spider completes)
   */
  async startActiveScan(targetUrl: string, policy?: string): Promise<string> {
    try {
      console.log('🎯 Starting ZAP active scan for:', targetUrl);
      const activeScanId = await this.zapClient.startActiveScan(targetUrl, policy);
      console.log('🎯 Active scan started with ID:', activeScanId);
      return activeScanId;
    } catch (error) {
      console.error('❌ Failed to start active scan:', error);
      throw error;
    }
  }

  /**
   * Convert ZAP alerts to JagaScan vulnerabilities
   */
  async getVulnerabilities(targetUrl?: string): Promise<Vulnerability[]> {
    try {
      const zapAlerts = await this.zapClient.getAlerts(targetUrl);
      return zapAlerts.map(alert => this.convertZAPAlertToVulnerability(alert));
    } catch (error) {
      console.error('❌ Error getting vulnerabilities:', error);
      return [];
    }
  }

  /**
   * Generate comprehensive report
   */
  async generateReport(title?: string): Promise<string> {
    try {
      return await this.zapClient.generateHtmlReport(title || 'JagaScan Security Report');
    } catch (error) {
      console.error('❌ Error generating report:', error);
      throw error;
    }
  }

  /**
   * Stop all running scans
   */
  async stopAllScans(): Promise<void> {
    try {
      await this.zapClient.stopAllScans();
      console.log('🛑 All ZAP scans stopped');
    } catch (error) {
      console.error('❌ Error stopping scans:', error);
      throw error;
    }
  }

  /**
   * Convert ZAP alert to JagaScan vulnerability format
   */
  private convertZAPAlertToVulnerability(alert: ZAPAlert): Vulnerability {
    const vulnerabilityType = this.mapZAPAlertToVulnerabilityType(alert.pluginId, alert.name);
    const severity = this.mapZAPRiskToSeverity(alert.riskDesc);
    
    return {
      id: `zap-${alert.pluginId}-${Date.now()}`,
      type: vulnerabilityType,
      severity,
      title: alert.name,
      description: alert.description,
      solution: alert.solution,
      evidence: alert.instances?.[0]?.evidence || '',
      location: alert.instances?.[0]?.uri || '',
      confidence: this.mapZAPConfidenceToNumber(alert.confidence)
    };
  }

  /**
   * Map ZAP plugin ID and name to JagaScan vulnerability type
   */
  private mapZAPAlertToVulnerabilityType(pluginId: string, name: string): VulnerabilityType {
    const lowerName = name.toLowerCase();
    
    if (lowerName.includes('sql injection') || pluginId === '40018') {
      return VulnerabilityType.SQL_INJECTION;
    } else if (lowerName.includes('cross site scripting') || lowerName.includes('xss') || pluginId === '40012') {
      return VulnerabilityType.XSS;
    } else if (lowerName.includes('csrf') || lowerName.includes('cross-site request forgery')) {
      return VulnerabilityType.CSRF;
    } else if (lowerName.includes('directory traversal') || lowerName.includes('path traversal')) {
      return VulnerabilityType.DIRECTORY_TRAVERSAL;
    } else if (lowerName.includes('information disclosure') || lowerName.includes('information leak')) {
      return VulnerabilityType.INFORMATION_DISCLOSURE;
    } else if (lowerName.includes('redirect') || pluginId === '10028') {
      return VulnerabilityType.OPEN_REDIRECT;
    } else if (lowerName.includes('authentication') || lowerName.includes('session')) {
      return VulnerabilityType.BROKEN_AUTHENTICATION;
    } else if (lowerName.includes('configuration') || lowerName.includes('header') || lowerName.includes('ssl')) {
      return VulnerabilityType.SECURITY_MISCONFIGURATION;
    } else if (lowerName.includes('sensitive') || lowerName.includes('exposure')) {
      return VulnerabilityType.SENSITIVE_DATA_EXPOSURE;
    } else {
      return VulnerabilityType.SECURITY_MISCONFIGURATION; // Default fallback
    }
  }

  /**
   * Map ZAP risk level to JagaScan severity
   */
  private mapZAPRiskToSeverity(riskDesc: string): Severity {
    switch (riskDesc.toLowerCase()) {
      case 'high':
        return Severity.HIGH;
      case 'medium':
        return Severity.MEDIUM;
      case 'low':
        return Severity.LOW;
      case 'informational':
        return Severity.INFO;
      default:
        return Severity.MEDIUM;
    }
  }

  /**
   * Map ZAP confidence to numeric value
   */
  private mapZAPConfidenceToNumber(confidence: string): number {
    switch (confidence.toLowerCase()) {
      case 'high':
        return 95;
      case 'medium':
        return 75;
      case 'low':
        return 50;
      default:
        return 60;
    }
  }

  /**
   * Monitor ZAP scan progress and update database
   */
  private async monitorZAPScanProgress(
    scanId: string,
    spiderScanId?: string,
    targetUrl?: string,
    options?: ZAPScanOptions
  ): Promise<void> {
    console.log('🔄 Starting ZAP scan monitoring for:', scanId);
    
    let spiderCompleted = false;
    let activeScanId: string | undefined;
    let activeScanStarted = false;

    // Monitor loop
    while (true) {
      try {
        // Check spider progress
        if (spiderScanId && !spiderCompleted) {
          const spiderStatus = await this.zapClient.getSpiderStatus(spiderScanId);
          console.log(`🕷️ Spider progress: ${spiderStatus.progress}%`);

          await scannerService.updateZAPScanProgress(scanId, {
            phase: 'spider',
            progress: spiderStatus.progress,
            currentTask: `Crawling website... ${spiderStatus.progress}% complete`
          });

          if (spiderStatus.progress >= 100) {
            spiderCompleted = true;
            console.log('✅ Spider scan completed');
          }
        }

        // Start active scan when spider is done
        if (spiderCompleted && !activeScanStarted && options?.enableActiveScan !== false && targetUrl) {
          console.log('🚀 Starting active scan...');
          activeScanId = await this.zapClient.startActiveScan(targetUrl);
          activeScanStarted = true;
          console.log('🎯 Active scan started with ID:', activeScanId);
        }

        // Check active scan progress
        if (activeScanId && activeScanStarted) {
          const activeStatus = await this.zapClient.getActiveScanStatus(activeScanId);
          console.log(`🎯 Active scan progress: ${activeStatus.progress}%`);

          await scannerService.updateZAPScanProgress(scanId, {
            phase: 'active',
            progress: activeStatus.progress,
            currentTask: `Testing for vulnerabilities... ${activeStatus.progress}% complete`
          });

          if (activeStatus.progress >= 100) {
            console.log('✅ Active scan completed');
            break;
          }
        }

        // If only spider scan, check if done
        if (spiderCompleted && options?.enableActiveScan === false) {
          console.log('✅ Spider-only scan completed');
          break;
        }

        // Wait before next check
        await new Promise(resolve => setTimeout(resolve, 5000));

      } catch (error) {
        console.error('❌ Error monitoring ZAP progress:', error);
        await scannerService.updateZAPScanProgress(scanId, {
          status: ScanStatus.FAILED,
          currentTask: 'Scan failed due to monitoring error'
        });
        break;
      }
    }

    // Scan completed, get final results
    try {
      console.log('📊 Getting final ZAP results...');
      const alerts = await this.zapClient.getAlerts();
      const vulnerabilities = alerts.map(alert => this.convertZAPAlertToVulnerability(alert));

      await scannerService.updateZAPScanProgress(scanId, {
        status: ScanStatus.COMPLETED,
        vulnerabilities,
        currentTask: 'Scan completed successfully',
        progress: 100
      });

      console.log(`✅ ZAP scan ${scanId} completed with ${vulnerabilities.length} vulnerabilities`);
    } catch (error) {
      console.error('❌ Error getting final results:', error);
      await scannerService.updateZAPScanProgress(scanId, {
        status: ScanStatus.FAILED,
        currentTask: 'Failed to retrieve scan results'
      });
    }
  }
}
