/**
 * OWASP ZAP Client for JagaScan Integration
 * Provides interface to communicate with ZAP REST API
 */

export interface ZAPConfig {
  zapUrl: string;
  apiKey: string;
  proxyHost?: string;
  proxyPort?: number;
  timeout?: number;
}

export interface ZAPAlert {
  id: string;
  name: string;
  riskDesc: string;
  confidence: string;
  description: string;
  solution: string;
  reference: string;
  instances: Array<{
    uri: string;
    method: string;
    param: string;
    evidence: string;
  }>;
  count: string;
  cweid: string;
  wascid: string;
  pluginId: string;
}

export interface ZAPScanStatus {
  status: number;
  progress: number;
  scanId?: string;
}

export class ZAPClient {
  private config: ZAPConfig;
  private baseUrl: string;

  constructor(config: ZAPConfig) {
    this.config = {
      timeout: 30000,
      ...config
    };
    this.baseUrl = `${config.zapUrl}/JSON`;
  }

  /**
   * Test ZAP connection and API key
   */
  async testConnection(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/core/view/version/?apikey=${this.config.apiKey}`, {
        method: 'GET',
        signal: AbortSignal.timeout(this.config.timeout!)
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      return data.version !== undefined;
    } catch (error) {
      console.error('ZAP connection test failed:', error);
      return false;
    }
  }

  /**
   * Get ZAP version information
   */
  async getVersion(): Promise<string> {
    try {
      const response = await fetch(`${this.baseUrl}/core/view/version/?apikey=${this.config.apiKey}`);
      const data = await response.json();
      return data.version;
    } catch (error) {
      console.error('Failed to get ZAP version:', error);
      throw error;
    }
  }

  /**
   * Start a spider scan
   */
  async startSpider(url: string, maxChildren?: number): Promise<string> {
    try {
      const params = new URLSearchParams({
        apikey: this.config.apiKey,
        url: url,
        ...(maxChildren && { maxChildren: maxChildren.toString() })
      });

      const response = await fetch(`${this.baseUrl}/spider/action/scan/?${params}`, {
        method: 'GET'
      });

      if (!response.ok) {
        throw new Error(`Failed to start spider: ${response.statusText}`);
      }

      const data = await response.json();
      return data.scan;
    } catch (error) {
      console.error('Failed to start spider scan:', error);
      throw error;
    }
  }

  /**
   * Get spider scan status
   */
  async getSpiderStatus(scanId?: string): Promise<ZAPScanStatus> {
    try {
      const params = new URLSearchParams({
        apikey: this.config.apiKey,
        ...(scanId && { scanId })
      });

      const response = await fetch(`${this.baseUrl}/spider/view/status/?${params}`);
      const data = await response.json();
      
      return {
        status: parseInt(data.status),
        progress: parseInt(data.status),
        scanId
      };
    } catch (error) {
      console.error('Failed to get spider status:', error);
      throw error;
    }
  }

  /**
   * Start an active scan
   */
  async startActiveScan(url: string, policy?: string): Promise<string> {
    try {
      const params = new URLSearchParams({
        apikey: this.config.apiKey,
        url: url,
        ...(policy && { scanPolicyName: policy })
      });

      const response = await fetch(`${this.baseUrl}/ascan/action/scan/?${params}`, {
        method: 'GET'
      });

      if (!response.ok) {
        throw new Error(`Failed to start active scan: ${response.statusText}`);
      }

      const data = await response.json();
      return data.scan;
    } catch (error) {
      console.error('Failed to start active scan:', error);
      throw error;
    }
  }

  /**
   * Get active scan status
   */
  async getActiveScanStatus(scanId?: string): Promise<ZAPScanStatus> {
    try {
      const params = new URLSearchParams({
        apikey: this.config.apiKey,
        ...(scanId && { scanId })
      });

      const response = await fetch(`${this.baseUrl}/ascan/view/status/?${params}`);
      const data = await response.json();
      
      return {
        status: parseInt(data.status),
        progress: parseInt(data.status),
        scanId
      };
    } catch (error) {
      console.error('Failed to get active scan status:', error);
      throw error;
    }
  }

  /**
   * Get all alerts from ZAP
   */
  async getAlerts(baseUrl?: string): Promise<ZAPAlert[]> {
    try {
      const params = new URLSearchParams({
        apikey: this.config.apiKey,
        ...(baseUrl && { baseurl: baseUrl })
      });

      const response = await fetch(`${this.baseUrl}/core/view/alerts/?${params}`);
      
      if (!response.ok) {
        throw new Error(`Failed to get alerts: ${response.statusText}`);
      }

      const data = await response.json();
      return data.alerts || [];
    } catch (error) {
      console.error('Failed to get ZAP alerts:', error);
      throw error;
    }
  }

  /**
   * Generate HTML report
   */
  async generateHtmlReport(title?: string): Promise<string> {
    try {
      const params = new URLSearchParams({
        apikey: this.config.apiKey,
        ...(title && { title })
      });

      const response = await fetch(`${this.baseUrl}/core/other/htmlreport/?${params}`);
      
      if (!response.ok) {
        throw new Error(`Failed to generate report: ${response.statusText}`);
      }

      return await response.text();
    } catch (error) {
      console.error('Failed to generate HTML report:', error);
      throw error;
    }
  }

  /**
   * Stop all scans
   */
  async stopAllScans(): Promise<void> {
    try {
      // Stop spider scans
      await fetch(`${this.baseUrl}/spider/action/stopAllScans/?apikey=${this.config.apiKey}`);
      
      // Stop active scans
      await fetch(`${this.baseUrl}/ascan/action/stopAllScans/?apikey=${this.config.apiKey}`);
    } catch (error) {
      console.error('Failed to stop scans:', error);
      throw error;
    }
  }

  /**
   * Add URL to context
   */
  async addUrlToContext(contextName: string, url: string): Promise<void> {
    try {
      const params = new URLSearchParams({
        apikey: this.config.apiKey,
        contextName,
        regex: `${url}.*`
      });

      const response = await fetch(`${this.baseUrl}/context/action/includeInContext/?${params}`);
      
      if (!response.ok) {
        throw new Error(`Failed to add URL to context: ${response.statusText}`);
      }
    } catch (error) {
      console.error('Failed to add URL to context:', error);
      throw error;
    }
  }

  /**
   * Access URLs through ZAP proxy
   */
  async accessUrl(url: string): Promise<void> {
    try {
      const response = await fetch(`${this.baseUrl}/core/action/accessUrl/?apikey=${this.config.apiKey}&url=${encodeURIComponent(url)}`);
      
      if (!response.ok) {
        throw new Error(`Failed to access URL: ${response.statusText}`);
      }
    } catch (error) {
      console.error('Failed to access URL through ZAP:', error);
      throw error;
    }
  }
}
