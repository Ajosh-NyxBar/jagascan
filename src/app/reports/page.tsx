'use client';

import { useState } from 'react';
import Link from 'next/link';
import { 
  Shield, 
  FileText, 
  Download, 
  Eye, 
  AlertTriangle,
  CheckCircle,
  Clock,
  Filter,
  Calendar,
  Search
} from 'lucide-react';
import { ScanResult, Severity, ScanStatus } from '@/types';

// Mock data
const mockReports: ScanResult[] = [
  {
    id: '1',
    targetId: 'target1',
    scanType: 'web_vulnerability' as any,
    status: 'completed' as ScanStatus,
    startTime: new Date('2024-12-20T10:30:00'),
    endTime: new Date('2024-12-20T10:45:00'),
    vulnerabilities: [
      {
        id: 'v1',
        type: 'sql_injection' as any,
        severity: 'high' as Severity,
        title: 'SQL Injection in login form',
        description: 'Vulnerable parameter found',
        location: '/login',
        confidence: 95
      },
      {
        id: 'v2',
        type: 'xss' as any,
        severity: 'medium' as Severity,
        title: 'Reflected XSS in search',
        description: 'User input not properly sanitized',
        location: '/search',
        confidence: 87
      }
    ],
    metadata: {
      duration: 900000,
      requestCount: 156,
      responseCount: 156,
      errorCount: 0,
      userAgent: 'JagaScan/1.0',
      scannerVersion: '1.0.0'
    }
  },
  {
    id: '2',
    targetId: 'target2',
    scanType: 'port_scan' as any,
    status: 'completed' as ScanStatus,
    startTime: new Date('2024-12-19T14:20:00'),
    endTime: new Date('2024-12-19T14:25:00'),
    vulnerabilities: [],
    metadata: {
      duration: 300000,
      requestCount: 65535,
      responseCount: 89,
      errorCount: 0,
      userAgent: 'JagaScan/1.0',
      scannerVersion: '1.0.0'
    }
  },
  {
    id: '3',
    targetId: 'target3',
    scanType: 'ssl_analysis' as any,
    status: 'running' as ScanStatus,
    startTime: new Date('2024-12-20T11:00:00'),
    vulnerabilities: [],
    metadata: {
      duration: 0,
      requestCount: 0,
      responseCount: 0,
      errorCount: 0,
      userAgent: 'JagaScan/1.0',
      scannerVersion: '1.0.0'
    }
  }
];

export default function ReportsPage() {
  const [reports, setReports] = useState<ScanResult[]>(mockReports);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<ScanStatus | 'all'>('all');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');

  const filteredReports = reports.filter(report => {
    const matchesSearch = searchTerm === '' || 
      report.scanType.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || report.status === statusFilter;
    const matchesSeverity = severityFilter === 'all' || 
      report.vulnerabilities.some(v => v.severity === severityFilter);
    
    return matchesSearch && matchesStatus && matchesSeverity;
  });

  const getSeverityColor = (severity: Severity) => {
    switch (severity) {
      case 'critical': return 'text-red-500 bg-red-500/10 border-red-500';
      case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500';
      case 'low': return 'text-blue-500 bg-blue-500/10 border-blue-500';
      case 'info': return 'text-gray-500 bg-gray-500/10 border-gray-500';
      default: return 'text-gray-500 bg-gray-500/10 border-gray-500';
    }
  };

  const getStatusIcon = (status: ScanStatus) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'running': return <Clock className="h-5 w-5 text-yellow-500" />;
      case 'failed': return <AlertTriangle className="h-5 w-5 text-red-500" />;
      default: return <Clock className="h-5 w-5 text-gray-500" />;
    }
  };

  const handleDownloadReport = (reportId: string, format: 'pdf' | 'html' | 'json') => {
    // Mock download functionality
    alert(`Downloading report ${reportId} as ${format.toUpperCase()}`);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white">
      {/* Navigation */}
      <nav className="border-b border-gray-700 bg-gray-900/50 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16 items-center">
            <Link href="/" className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-red-500" />
              <span className="text-xl font-bold">JagaScan</span>
            </Link>
            <div className="hidden md:flex items-center space-x-8">
              <Link href="/dashboard" className="hover:text-red-400 transition-colors">
                Dashboard
              </Link>
              <Link href="/scan" className="hover:text-red-400 transition-colors">
                New Scan
              </Link>
              <Link href="/reports" className="text-red-400 border-b-2 border-red-400 pb-1">
                Reports
              </Link>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">Scan Reports</h1>
          <p className="text-gray-400">View and download security scan reports</p>
        </div>

        {/* Filters */}
        <div className="bg-gray-800/50 rounded-lg border border-gray-700 p-6 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Search</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search reports..."
                  className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent"
                />
              </div>
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-2">Status</label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as ScanStatus | 'all')}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent"
              >
                <option value="all">All Statuses</option>
                <option value="completed">Completed</option>
                <option value="running">Running</option>
                <option value="failed">Failed</option>
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-2">Severity</label>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as Severity | 'all')}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            
            <div className="flex items-end">
              <button className="w-full bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg font-medium transition-colors flex items-center justify-center gap-2">
                <Filter className="h-4 w-4" />
                Apply Filters
              </button>
            </div>
          </div>
        </div>

        {/* Reports List */}
        <div className="space-y-4">
          {filteredReports.map((report) => (
            <div key={report.id} className="bg-gray-800/50 rounded-lg border border-gray-700 p-6">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-3">
                  {getStatusIcon(report.status)}
                  <div>
                    <h3 className="text-lg font-semibold capitalize">
                      {report.scanType.replace('_', ' ')} Scan
                    </h3>
                    <p className="text-gray-400 text-sm">
                      Started: {report.startTime.toLocaleString()}
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => alert(`Viewing report ${report.id}`)}
                    className="bg-blue-600 hover:bg-blue-700 px-3 py-1 rounded text-sm font-medium transition-colors flex items-center gap-1"
                  >
                    <Eye className="h-4 w-4" />
                    View
                  </button>
                  <div className="relative group">
                    <button className="bg-green-600 hover:bg-green-700 px-3 py-1 rounded text-sm font-medium transition-colors flex items-center gap-1">
                      <Download className="h-4 w-4" />
                      Download
                    </button>
                    <div className="absolute right-0 mt-2 w-32 bg-gray-700 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                      <button
                        onClick={() => handleDownloadReport(report.id, 'pdf')}
                        className="block w-full text-left px-4 py-2 text-sm hover:bg-gray-600 rounded-t-lg"
                      >
                        PDF
                      </button>
                      <button
                        onClick={() => handleDownloadReport(report.id, 'html')}
                        className="block w-full text-left px-4 py-2 text-sm hover:bg-gray-600"
                      >
                        HTML
                      </button>
                      <button
                        onClick={() => handleDownloadReport(report.id, 'json')}
                        className="block w-full text-left px-4 py-2 text-sm hover:bg-gray-600 rounded-b-lg"
                      >
                        JSON
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
                <div>
                  <p className="text-sm text-gray-400">Status</p>
                  <p className="font-medium capitalize">{report.status}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Duration</p>
                  <p className="font-medium">
                    {report.endTime 
                      ? `${Math.round((report.endTime.getTime() - report.startTime.getTime()) / 60000)}m`
                      : 'Running...'
                    }
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Requests</p>
                  <p className="font-medium">{report.metadata.requestCount}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Vulnerabilities</p>
                  <p className="font-medium">{report.vulnerabilities.length}</p>
                </div>
              </div>

              {report.vulnerabilities.length > 0 && (
                <div>
                  <h4 className="font-medium mb-2">Vulnerabilities Found:</h4>
                  <div className="space-y-2">
                    {report.vulnerabilities.slice(0, 3).map((vuln) => (
                      <div key={vuln.id} className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <span className={`px-2 py-1 rounded-full text-xs border ${getSeverityColor(vuln.severity)}`}>
                            {vuln.severity.toUpperCase()}
                          </span>
                          <span className="text-sm">{vuln.title}</span>
                        </div>
                        <span className="text-xs text-gray-400">{vuln.location}</span>
                      </div>
                    ))}
                    {report.vulnerabilities.length > 3 && (
                      <p className="text-sm text-gray-400">
                        +{report.vulnerabilities.length - 3} more vulnerabilities
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>

        {filteredReports.length === 0 && (
          <div className="text-center py-12">
            <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium mb-2">No reports found</h3>
            <p className="text-gray-400 mb-4">
              {searchTerm || statusFilter !== 'all' || severityFilter !== 'all'
                ? 'Try adjusting your filters'
                : 'Start a scan to generate your first report'
              }
            </p>
            <Link
              href="/scan"
              className="bg-red-600 hover:bg-red-700 px-6 py-2 rounded-lg font-medium transition-colors inline-flex items-center gap-2"
            >
              <FileText className="h-4 w-4" />
              Start New Scan
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
