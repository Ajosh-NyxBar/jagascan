// Scan related types
export interface ScanTarget {
  id: string;
  url: string;
  domain: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ScanResult {
  id: string;
  targetId: string;
  scanType: ScanType;
  status: ScanStatus;
  startTime: Date;
  endTime?: Date;
  vulnerabilities: Vulnerability[];
  metadata: ScanMetadata;
}

export interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  severity: Severity;
  title: string;
  description: string;
  solution?: string;
  evidence?: string;
  location: string;
  confidence: number;
}

export enum ScanType {
  WEB_VULNERABILITY = 'web_vulnerability',
  PORT_SCAN = 'port_scan',
  SSL_ANALYSIS = 'ssl_analysis',
  DIRECTORY_ENUM = 'directory_enum',
  SQL_INJECTION = 'sql_injection',
  XSS = 'xss'
}

export enum ScanStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled'
}

export enum VulnerabilityType {
  SQL_INJECTION = 'sql_injection',
  XSS = 'xss',
  CSRF = 'csrf',
  OPEN_REDIRECT = 'open_redirect',
  DIRECTORY_TRAVERSAL = 'directory_traversal',
  INFORMATION_DISCLOSURE = 'information_disclosure',
  BROKEN_AUTHENTICATION = 'broken_authentication',
  SECURITY_MISCONFIGURATION = 'security_misconfiguration',
  SENSITIVE_DATA_EXPOSURE = 'sensitive_data_exposure',
  INSECURE_DESERIALIZATION = 'insecure_deserialization'
}

export enum Severity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info'
}

export interface ScanMetadata {
  duration: number; // in milliseconds
  requestCount: number;
  responseCount: number;
  errorCount: number;
  userAgent: string;
  scannerVersion: string;
  zapConfig?: any; // For ZAP-enhanced scans
}

export interface ScanRequest {
  target: string;
  scanTypes: ScanType[];
  options?: ScanOptions;
}

export interface ScanOptions {
  maxDepth?: number;
  followRedirects?: boolean;
  timeout?: number;
  userAgent?: string;
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
  excludePatterns?: string[];
}

// Dashboard types
export interface DashboardStats {
  totalScans: number;
  activeScans: number;
  vulnerabilitiesFound: number;
  criticalVulnerabilities: number;
  recentScans: ScanResult[];
}

// Report types
export interface ReportConfig {
  format: ReportFormat;
  includeEvidence: boolean;
  includeSolutions: boolean;
  severityFilter?: Severity[];
}

export enum ReportFormat {
  PDF = 'pdf',
  HTML = 'html',
  JSON = 'json',
  XML = 'xml'
}

// API Response types
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  hasNext: boolean;
  hasPrev: boolean;
}
