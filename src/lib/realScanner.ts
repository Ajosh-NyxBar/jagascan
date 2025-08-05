import { HttpClient, ResponseAnalyzer, PayloadGenerator, URLDiscovery } from './httpClient';
import { VulnerabilityType, Severity } from '@/types';

// Define interface yang kompatibel dengan real implementation
export interface RealVulnerability {
  id: string;
  type: VulnerabilityType;
  severity: Severity;
  title: string;
  description: string;
  location: string;
  confidence: number;
  evidence?: string;
  solution?: string;
  parameter?: string;
  payload?: string;
}

export interface ScanProgress {
  current: number;
  total: number;
  status: string;
  currentTest?: string;
  errors?: string[];
}

/**
 * Real Web Vulnerability Scanner with HTTP requests and payload testing
 */
export class RealWebVulnerabilityScanner {
  private url: string;
  private client: HttpClient;
  private vulnerabilities: RealVulnerability[] = [];
  private progress: ScanProgress = { current: 0, total: 0, status: 'idle' };
  private onProgressUpdate?: (progress: ScanProgress) => void;

  constructor(url: string, options: { 
    timeout?: number; 
    userAgent?: string;
    onProgressUpdate?: (progress: ScanProgress) => void;
  } = {}) {
    this.url = url;
    this.client = new HttpClient({
      timeout: options.timeout || 30000,
      userAgent: options.userAgent || 'JagaScan/1.0'
    });
    this.onProgressUpdate = options.onProgressUpdate;
  }

  private updateProgress(current: number, total: number, status: string, currentTest?: string, errors?: string[]) {
    this.progress = { current, total, status, currentTest, errors };
    if (this.onProgressUpdate) {
      this.onProgressUpdate(this.progress);
    }
  }

  private addVulnerability(vuln: Omit<RealVulnerability, 'id'>) {
    const vulnerability: RealVulnerability = {
      id: `vuln_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...vuln
    };
    this.vulnerabilities.push(vulnerability);
  }

  /**
   * Perform comprehensive vulnerability scan
   */
  async scan(): Promise<RealVulnerability[]> {
    this.vulnerabilities = [];
    this.updateProgress(0, 100, 'starting', 'Initializing scan...');

    try {
      // Test 1: Basic connectivity and information gathering
      this.updateProgress(5, 100, 'running', 'Testing basic connectivity...');
      await this.testConnectivity();

      // Test 2: SSL/TLS Security
      this.updateProgress(15, 100, 'running', 'Checking SSL/TLS configuration...');
      await this.checkSSLSecurity();

      // Test 3: HTTP Security Headers
      this.updateProgress(25, 100, 'running', 'Analyzing HTTP security headers...');
      await this.checkSecurityHeaders();

      // Test 4: Directory and file discovery
      this.updateProgress(35, 100, 'running', 'Discovering directories and files...');
      await this.discoverPaths();

      // Test 5: SQL Injection testing
      this.updateProgress(50, 100, 'running', 'Testing for SQL injection vulnerabilities...');
      await this.testSQLInjection();

      // Test 6: XSS testing
      this.updateProgress(70, 100, 'running', 'Testing for Cross-Site Scripting (XSS)...');
      await this.testXSS();

      // Test 7: CSRF testing
      this.updateProgress(80, 100, 'running', 'Testing for Cross-Site Request Forgery (CSRF)...');
      await this.testCSRF();

      // Test 8: Directory traversal
      this.updateProgress(90, 100, 'running', 'Testing for directory traversal...');
      await this.testDirectoryTraversal();

      // Test 9: Command injection
      this.updateProgress(95, 100, 'running', 'Testing for command injection...');
      await this.testCommandInjection();

      this.updateProgress(100, 100, 'completed', 'Scan completed successfully');
      return this.vulnerabilities;

    } catch (error) {
      this.updateProgress(this.progress.current, 100, 'error', 'Scan failed', [String(error)]);
      throw error;
    }
  }

  /**
   * Test basic connectivity and gather information
   */
  private async testConnectivity(): Promise<void> {
    try {
      const response = await this.client.get(this.url);
      const analysis = ResponseAnalyzer.analyzeResponse(response);

      // Check for server information disclosure
      const serverHeader = analysis.headers['server'];
      if (serverHeader && serverHeader.includes('/')) {
        this.addVulnerability({
          type: VulnerabilityType.INFORMATION_DISCLOSURE,
          severity: Severity.LOW,
          title: 'Server Version Disclosure',
          description: `The server reveals version information: ${serverHeader}`,
          location: this.url,
          evidence: `Server: ${serverHeader}`,
          solution: 'Hide server version information to prevent attackers from identifying specific vulnerabilities.',
          confidence: 0.8
        });
      }

      // Check for powered-by headers
      const poweredBy = analysis.headers['x-powered-by'];
      if (poweredBy) {
        this.addVulnerability({
          type: VulnerabilityType.INFORMATION_DISCLOSURE,
          severity: Severity.LOW,
          title: 'Technology Stack Disclosure',
          description: `The application reveals technology stack: ${poweredBy}`,
          location: this.url,
          evidence: `X-Powered-By: ${poweredBy}`,
          solution: 'Remove or customize X-Powered-By headers to prevent technology stack fingerprinting.',
          confidence: 0.9
        });
      }

      // Check for debug information
      if (analysis.hasDebugInfo) {
        this.addVulnerability({
          type: VulnerabilityType.INFORMATION_DISCLOSURE,
          severity: Severity.MEDIUM,
          title: 'Debug Information Exposure',
          description: 'The application exposes debug information that could aid attackers.',
          location: this.url,
          evidence: 'Debug information found in response',
          solution: 'Disable debug mode in production environments.',
          confidence: 0.7
        });
      }

    } catch (error) {
      this.addVulnerability({
        type: VulnerabilityType.SECURITY_MISCONFIGURATION,
        severity: Severity.MEDIUM,
        title: 'Connection Issues',
        description: `Unable to establish proper connection: ${error}`,
        location: this.url,
        solution: 'Verify server configuration and network connectivity.',
        confidence: 0.5
      });
    }
  }

  /**
   * Check SSL/TLS security configuration
   */
  private async checkSSLSecurity(): Promise<void> {
    try {
      const urlObj = new URL(this.url);
      
      if (urlObj.protocol === 'http:') {
        this.addVulnerability({
          type: VulnerabilityType.SECURITY_MISCONFIGURATION,
          severity: Severity.HIGH,
          title: 'Unencrypted HTTP Connection',
          description: 'The application does not use HTTPS, making it vulnerable to man-in-the-middle attacks.',
          location: this.url,
          evidence: 'Using HTTP instead of HTTPS',
          solution: 'Implement HTTPS with proper SSL/TLS certificates and redirect all HTTP traffic to HTTPS.',
          confidence: 1.0
        });
      }

    } catch (error) {
      console.error('SSL Security check failed:', error);
    }
  }

  /**
   * Check HTTP security headers
   */
  private async checkSecurityHeaders(): Promise<void> {
    try {
      const response = await this.client.get(this.url);
      const headers = ResponseAnalyzer.analyzeResponse(response).headers;

      const securityHeaders = {
        'strict-transport-security': {
          name: 'HTTP Strict Transport Security (HSTS)',
          severity: Severity.MEDIUM,
          description: 'HSTS header is missing, which could allow downgrade attacks.'
        },
        'content-security-policy': {
          name: 'Content Security Policy (CSP)',
          severity: Severity.MEDIUM,
          description: 'CSP header is missing, increasing XSS attack risk.'
        },
        'x-frame-options': {
          name: 'X-Frame-Options',
          severity: Severity.MEDIUM,
          description: 'X-Frame-Options header is missing, making the site vulnerable to clickjacking.'
        }
      };

      for (const [headerName, config] of Object.entries(securityHeaders)) {
        if (!headers[headerName] && !headers[headerName.toLowerCase()]) {
          this.addVulnerability({
            type: VulnerabilityType.SECURITY_MISCONFIGURATION,
            severity: config.severity,
            title: `Missing ${config.name}`,
            description: config.description,
            location: this.url,
            evidence: `${headerName} header not found`,
            solution: `Implement ${config.name} header with appropriate values.`,
            confidence: 0.9
          });
        }
      }

    } catch (error) {
      console.error('Security headers check failed:', error);
    }
  }

  /**
   * Discover paths and sensitive files
   */
  private async discoverPaths(): Promise<void> {
    try {
      const discovery = new URLDiscovery(this.url, this.client);
      const paths = await discovery.discoverCommonPaths();

      for (const path of paths.slice(0, 10)) { // Limit to first 10 paths to avoid long scan times
        if (path.exists && path.status === 200) {
          // Check for sensitive files
          const sensitivePatterns = [
            { pattern: /\.(env|config|ini|conf)$/i, severity: Severity.HIGH },
            { pattern: /\.(log|backup|bak|old|tmp)$/i, severity: Severity.MEDIUM },
            { pattern: /\/(admin|phpmyadmin|wp-admin)/i, severity: Severity.MEDIUM },
            { pattern: /\.(git|svn)/i, severity: Severity.HIGH }
          ];

          for (const { pattern, severity } of sensitivePatterns) {
            if (pattern.test(path.url)) {
              this.addVulnerability({
                type: VulnerabilityType.INFORMATION_DISCLOSURE,
                severity,
                title: 'Sensitive File/Directory Accessible',
                description: `Sensitive file or directory is publicly accessible: ${path.url}`,
                location: path.url,
                evidence: `HTTP ${path.status} response`,
                solution: 'Restrict access to sensitive files and directories.',
                confidence: 0.9
              });
              break;
            }
          }
        }
      }

    } catch (error) {
      console.error('Path discovery failed:', error);
    }
  }

  /**
   * Test for SQL injection vulnerabilities (Public method)
   */
  async testSQLInjection(): Promise<void> {
    try {
      // Get initial page to find forms
      const response = await this.client.get(this.url);
      const forms = ResponseAnalyzer.extractForms(response.data);
      const payloads = PayloadGenerator.getSQLInjectionPayloads();

      // Test URL parameters
      const urlObj = new URL(this.url);
      if (urlObj.searchParams.size > 0) {
        for (const [param, value] of urlObj.searchParams.entries()) {
          for (const payload of payloads.slice(0, 3)) { // Test first 3 payloads
            try {
              const testUrl = new URL(this.url);
              testUrl.searchParams.set(param, payload);
              
              const testResponse = await this.client.get(testUrl.toString());
              const analysis = ResponseAnalyzer.analyzeResponse(testResponse);
              
              if (analysis.hasSQLErrors) {
                this.addVulnerability({
                  type: VulnerabilityType.SQL_INJECTION,
                  severity: Severity.HIGH,
                  title: 'SQL Injection in URL Parameter',
                  description: 'SQL injection vulnerability detected in URL parameter.',
                  location: testUrl.toString(),
                  parameter: param,
                  payload,
                  evidence: 'SQL error messages detected in response',
                  solution: 'Use parameterized queries and input validation to prevent SQL injection.',
                  confidence: 0.9
                });
                break; // Found vulnerability, move to next parameter
              }
            } catch {
              // Ignore individual test failures
            }
          }
        }
      }

    } catch (error) {
      console.error('SQL injection test failed:', error);
    }
  }

  /**
   * Test for XSS vulnerabilities (Public method)
   */
  async testXSS(): Promise<void> {
    try {
      const response = await this.client.get(this.url);
      const forms = ResponseAnalyzer.extractForms(response.data);
      const payloads = PayloadGenerator.getXSSPayloads();

      // Test URL parameters for reflected XSS
      const urlObj = new URL(this.url);
      if (urlObj.searchParams.size > 0) {
        for (const [param, value] of urlObj.searchParams.entries()) {
          for (const payload of payloads.slice(0, 3)) { // Test first 3 payloads
            try {
              const testUrl = new URL(this.url);
              testUrl.searchParams.set(param, payload);
              
              const testResponse = await this.client.get(testUrl.toString());
              
              if (testResponse.data.includes(payload)) {
                this.addVulnerability({
                  type: VulnerabilityType.XSS,
                  severity: Severity.HIGH,
                  title: 'Reflected XSS in URL Parameter',
                  description: 'Reflected XSS vulnerability detected in URL parameter.',
                  location: testUrl.toString(),
                  parameter: param,
                  payload,
                  evidence: 'Payload reflected in response without proper encoding',
                  solution: 'Implement proper input validation and output encoding to prevent XSS attacks.',
                  confidence: 0.8
                });
                break; // Found vulnerability, move to next parameter
              }
            } catch {
              // Ignore individual test failures
            }
          }
        }
      }

    } catch (error) {
      console.error('XSS test failed:', error);
    }
  }

  /**
   * Test for CSRF vulnerabilities (Public method)
   */
  async testCSRF(): Promise<void> {
    try {
      const response = await this.client.get(this.url);
      const forms = ResponseAnalyzer.extractForms(response.data);

      for (const form of forms) {
        if (form.method === 'POST') {
          if (!form.hasCSRFToken) {
            this.addVulnerability({
              type: VulnerabilityType.CSRF,
              severity: Severity.MEDIUM,
              title: 'Missing CSRF Protection',
              description: 'Form lacks CSRF protection tokens.',
              location: new URL(form.action || this.url, this.url).toString(),
              evidence: 'No CSRF token found in form',
              solution: 'Implement CSRF tokens for all state-changing operations.',
              confidence: 0.7
            });
          }
        }
      }

    } catch (error) {
      console.error('CSRF test failed:', error);
    }
  }

  /**
   * Test for directory traversal vulnerabilities
   */
  private async testDirectoryTraversal(): Promise<void> {
    try {
      const payloads = PayloadGenerator.getDirectoryTraversalPayloads();
      const urlObj = new URL(this.url);

      // Test URL parameters
      if (urlObj.searchParams.size > 0) {
        for (const [param, value] of urlObj.searchParams.entries()) {
          for (const payload of payloads.slice(0, 3)) { // Test first 3 payloads
            try {
              const testUrl = new URL(this.url);
              testUrl.searchParams.set(param, payload + 'etc/passwd');
              
              const testResponse = await this.client.get(testUrl.toString());
              
              if (testResponse.data.includes('root:') || testResponse.data.includes('/bin/bash')) {
                this.addVulnerability({
                  type: VulnerabilityType.DIRECTORY_TRAVERSAL,
                  severity: Severity.HIGH,
                  title: 'Directory Traversal in URL Parameter',
                  description: 'Directory traversal vulnerability detected.',
                  location: testUrl.toString(),
                  parameter: param,
                  payload: payload + 'etc/passwd',
                  evidence: 'System file contents detected in response',
                  solution: 'Implement proper input validation and file access controls.',
                  confidence: 0.9
                });
                break;
              }
            } catch {
              // Ignore individual test failures
            }
          }
        }
      }

    } catch (error) {
      console.error('Directory traversal test failed:', error);
    }
  }

  /**
   * Test for command injection vulnerabilities
   */
  private async testCommandInjection(): Promise<void> {
    try {
      const payloads = PayloadGenerator.getCommandInjectionPayloads();
      const urlObj = new URL(this.url);

      // Test URL parameters
      if (urlObj.searchParams.size > 0) {
        for (const [param, value] of urlObj.searchParams.entries()) {
          for (const payload of payloads.slice(0, 3)) { // Test first 3 payloads
            try {
              const testUrl = new URL(this.url);
              testUrl.searchParams.set(param, payload);
              
              const testResponse = await this.client.get(testUrl.toString());
              
              // Look for command output patterns
              if (testResponse.data.includes('uid=') || 
                  testResponse.data.includes('total ') ||
                  testResponse.data.includes('Volume in drive') ||
                  testResponse.data.includes('127.0.0.1')) {
                this.addVulnerability({
                  type: VulnerabilityType.SECURITY_MISCONFIGURATION,
                  severity: Severity.CRITICAL,
                  title: 'Command Injection in URL Parameter',
                  description: 'Command injection vulnerability detected.',
                  location: testUrl.toString(),
                  parameter: param,
                  payload,
                  evidence: 'Command output detected in response',
                  solution: 'Avoid executing system commands based on user input. Use input validation and safe APIs.',
                  confidence: 0.9
                });
                break;
              }
            } catch {
              // Ignore individual test failures
            }
          }
        }
      }

    } catch (error) {
      console.error('Command injection test failed:', error);
    }
  }

  getProgress(): ScanProgress {
    return this.progress;
  }

  getVulnerabilities(): RealVulnerability[] {
    return this.vulnerabilities;
  }
}

// Legacy compatibility functions for existing API endpoints
export const checkSQLInjectionReal = async (url: string): Promise<RealVulnerability[]> => {
  const scanner = new RealWebVulnerabilityScanner(url);
  await scanner.testSQLInjection();
  return scanner.getVulnerabilities().filter(v => v.type === VulnerabilityType.SQL_INJECTION);
};

export const checkXSSReal = async (url: string): Promise<RealVulnerability[]> => {
  const scanner = new RealWebVulnerabilityScanner(url);
  await scanner.testXSS();
  return scanner.getVulnerabilities().filter(v => v.type === VulnerabilityType.XSS);
};

export const checkCSRFReal = async (url: string): Promise<RealVulnerability[]> => {
  const scanner = new RealWebVulnerabilityScanner(url);
  await scanner.testCSRF();
  return scanner.getVulnerabilities().filter(v => v.type === VulnerabilityType.CSRF);
};
