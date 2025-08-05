import { ScanTarget, Severity } from '@/types';

/**
 * Validates if a URL is properly formatted
 */
export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validates if a domain is properly formatted
 */
export function isValidDomain(domain: string): boolean {
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
  return domainRegex.test(domain);
}

/**
 * Normalizes a target input (URL or domain) to a proper URL
 */
export function normalizeTarget(target: string): string {
  // Remove whitespace
  target = target.trim();
  
  // If it's already a URL, return as is
  if (target.startsWith('http://') || target.startsWith('https://')) {
    return target;
  }
  
  // If it's just a domain, add https://
  if (isValidDomain(target)) {
    return `https://${target}`;
  }
  
  throw new Error('Invalid target format');
}

/**
 * Extracts domain from URL
 */
export function extractDomain(url: string): string {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname;
  } catch {
    throw new Error('Invalid URL format');
  }
}

/**
 * Formats scan duration from milliseconds to human readable format
 */
export function formatDuration(milliseconds: number): string {
  const seconds = Math.floor(milliseconds / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  
  if (hours > 0) {
    return `${hours}h ${minutes % 60}m`;
  } else if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  } else {
    return `${seconds}s`;
  }
}

/**
 * Gets severity color classes for UI components
 */
export function getSeverityColorClasses(severity: Severity): {
  text: string;
  bg: string;
  border: string;
} {
  switch (severity) {
    case 'critical':
      return {
        text: 'text-red-500',
        bg: 'bg-red-500/10',
        border: 'border-red-500'
      };
    case 'high':
      return {
        text: 'text-orange-500',
        bg: 'bg-orange-500/10',
        border: 'border-orange-500'
      };
    case 'medium':
      return {
        text: 'text-yellow-500',
        bg: 'bg-yellow-500/10',
        border: 'border-yellow-500'
      };
    case 'low':
      return {
        text: 'text-blue-500',
        bg: 'bg-blue-500/10',
        border: 'border-blue-500'
      };
    case 'info':
      return {
        text: 'text-gray-500',
        bg: 'bg-gray-500/10',
        border: 'border-gray-500'
      };
    default:
      return {
        text: 'text-gray-500',
        bg: 'bg-gray-500/10',
        border: 'border-gray-500'
      };
  }
}

/**
 * Validates scan target for security (basic checks)
 */
export function validateScanTarget(target: string): {
  isValid: boolean;
  error?: string;
} {
  try {
    const normalizedTarget = normalizeTarget(target);
    const domain = extractDomain(normalizedTarget);
    
    // Check for localhost/internal IPs (basic security)
    const internalPatterns = [
      /^localhost$/i,
      /^127\./,
      /^192\.168\./,
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^::1$/,
      /^0\.0\.0\.0$/
    ];
    
    for (const pattern of internalPatterns) {
      if (pattern.test(domain)) {
        return {
          isValid: false,
          error: 'Scanning internal/localhost targets is not allowed'
        };
      }
    }
    
    return { isValid: true };
    
  } catch (error) {
    return {
      isValid: false,
      error: error instanceof Error ? error.message : 'Invalid target format'
    };
  }
}

/**
 * Generates a unique scan ID
 */
export function generateScanId(): string {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 8);
  return `scan_${timestamp}_${random}`;
}

/**
 * Generates a target ID based on the target URL/domain
 */
export function generateTargetId(target: string): string {
  const normalizedTarget = normalizeTarget(target);
  const domain = extractDomain(normalizedTarget);
  const hash = Buffer.from(domain).toString('base64').substring(0, 8);
  return `target_${hash}`;
}

/**
 * Debounce function for search inputs
 */
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout;
  
  return (...args: Parameters<T>) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
}

/**
 * Formats file size in bytes to human readable format
 */
export function formatFileSize(bytes: number): string {
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  if (bytes === 0) return '0 Bytes';
  
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return Math.round((bytes / Math.pow(1024, i)) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Sanitizes user input to prevent XSS
 */
export function sanitizeInput(input: string): string {
  return input
    .replace(/[<>'"&]/g, (char) => {
      switch (char) {
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '"': return '&quot;';
        case "'": return '&#x27;';
        case '&': return '&amp;';
        default: return char;
      }
    });
}
