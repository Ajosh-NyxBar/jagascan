'use client';

import { useState, useEffect } from 'react';
import { 
  CheckCircle, 
  AlertTriangle, 
  Clock, 
  Shield, 
  Bug, 
  Eye, 
  Download,
  Activity,
  TrendingUp,
  FileText,
  Target,
  Globe
} from 'lucide-react';
import { ScanResult, Severity, ScanStatus, ScanType } from '@/types';

interface ScanResultDisplayProps {
  scanId: string;
  onClose?: () => void;
  showFullReport?: boolean;
}

interface ScanProgressData {
  status: ScanStatus;
  progress: number;
  currentTask: string;
  vulnerabilitiesFound: number;
  elapsed: number;
  scanType: ScanType;
}

export default function ScanResultDisplay({ 
  scanId, 
  onClose, 
  showFullReport = false 
}: ScanResultDisplayProps) {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [progressData, setProgressData] = useState<ScanProgressData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchScanData();
    
    // Poll for updates if scan is still running
    const interval = setInterval(() => {
      if (progressData?.status === ScanStatus.RUNNING) {
        fetchScanData();
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [scanId]);

  const fetchScanData = async () => {
    try {
      // Fetch scan result
      const resultResponse = await fetch(`/api/scan/${scanId}`);
      if (resultResponse.ok) {
        const resultData = await resultResponse.json();
        if (resultData.success) {
          setScanResult(resultData.data);
        }
      }

      // Fetch progress data
      const progressResponse = await fetch(`/api/scan/${scanId}/progress`);
      if (progressResponse.ok) {
        const progressData = await progressResponse.json();
        if (progressData.success) {
          setProgressData(progressData.data);
        }
      }
      
      setLoading(false);
    } catch (err) {
      setError('Failed to fetch scan data');
      setLoading(false);
    }
  };

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
      case ScanStatus.COMPLETED: 
        return <CheckCircle className="h-6 w-6 text-green-500" />;
      case ScanStatus.RUNNING: 
        return <Activity className="h-6 w-6 text-blue-500 animate-pulse" />;
      case ScanStatus.FAILED: 
        return <AlertTriangle className="h-6 w-6 text-red-500" />;
      default: 
        return <Clock className="h-6 w-6 text-gray-500" />;
    }
  };

  const getScanTypeIcon = (scanType: ScanType) => {
    switch (scanType) {
      case ScanType.WEB_VULNERABILITY: return <Globe className="h-5 w-5" />;
      case ScanType.PORT_SCAN: return <Target className="h-5 w-5" />;
      default: return <Shield className="h-5 w-5" />;
    }
  };

  const formatDuration = (milliseconds: number) => {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  };

  const getVulnerabilityCounts = () => {
    if (!scanResult) return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    
    return scanResult.vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
      return acc;
    }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>);
  };

  const handleDownload = (format: 'pdf' | 'html' | 'json') => {
    // Mock download functionality
    alert(`Downloading scan report ${scanId} as ${format.toUpperCase()}`);
  };

  if (loading) {
    return (
      <div className="bg-gray-800/50 rounded-lg border border-gray-700 p-8">
        <div className="flex items-center justify-center">
          <Activity className="h-6 w-6 text-blue-500 animate-spin mr-3" />
          <span>Loading scan data...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-900/20 border border-red-500 rounded-lg p-6">
        <div className="flex items-center">
          <AlertTriangle className="h-6 w-6 text-red-500 mr-3" />
          <span className="text-red-400">{error}</span>
        </div>
      </div>
    );
  }

  if (!progressData) return null;

  const vulnerabilityCounts = getVulnerabilityCounts();

  return (
    <div className="bg-gray-800/50 rounded-lg border border-gray-700 overflow-hidden">
      {/* Header */}
      <div className="bg-gray-900/50 p-6 border-b border-gray-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            {getStatusIcon(progressData.status)}
            <div>
              <h3 className="text-xl font-bold flex items-center gap-2">
                {getScanTypeIcon(progressData.scanType)}
                Scan Complete
              </h3>
              <p className="text-gray-400">
                Scan ID: {scanId} • {formatDuration(progressData.elapsed)}
              </p>
            </div>
          </div>
          
          <div className="flex items-center space-x-2">
            {onClose && (
              <button
                onClick={onClose}
                className="px-4 py-2 bg-gray-600 hover:bg-gray-700 rounded-lg text-sm transition-colors"
              >
                Close
              </button>
            )}
            <button
              onClick={() => handleDownload('pdf')}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
            >
              <Download className="h-4 w-4" />
              Download PDF
            </button>
          </div>
        </div>
      </div>

      {/* Status Banner */}
      {progressData.status === ScanStatus.COMPLETED && (
        <div className="bg-gradient-to-r from-green-900/30 to-emerald-900/30 border-b border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="bg-green-500/20 p-3 rounded-full">
                <CheckCircle className="h-8 w-8 text-green-400" />
              </div>
              <div>
                <h4 className="text-lg font-semibold text-green-400">Scan Completed Successfully</h4>
                <p className="text-gray-300">{progressData.currentTask}</p>
              </div>
            </div>
            <div className="text-right">
              <div className="text-2xl font-bold text-green-400">
                {progressData.vulnerabilitiesFound}
              </div>
              <div className="text-sm text-gray-400">Vulnerabilities Found</div>
            </div>
          </div>
        </div>
      )}

      {/* Progress Bar (if still running) */}
      {progressData.status === ScanStatus.RUNNING && (
        <div className="p-6 border-b border-gray-700">
          <div className="flex justify-between text-sm mb-2">
            <span className="text-gray-400">{progressData.currentTask}</span>
            <span className="text-gray-400">{Math.round(progressData.progress)}%</span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div
              className="bg-blue-500 h-2 rounded-full transition-all duration-300"
              style={{ width: `${progressData.progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Statistics Grid */}
      <div className="p-6 border-b border-gray-700">
        <h4 className="text-lg font-semibold mb-4">Scan Statistics</h4>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-gray-900/50 p-4 rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Duration</p>
                <p className="text-lg font-semibold">{formatDuration(progressData.elapsed)}</p>
              </div>
              <Clock className="h-5 w-5 text-gray-400" />
            </div>
          </div>
          
          <div className="bg-gray-900/50 p-4 rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Total Issues</p>
                <p className="text-lg font-semibold text-red-400">{progressData.vulnerabilitiesFound}</p>
              </div>
              <Bug className="h-5 w-5 text-red-400" />
            </div>
          </div>
          
          <div className="bg-gray-900/50 p-4 rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Scan Type</p>
                <p className="text-lg font-semibold capitalize">
                  {progressData.scanType.replace('_', ' ')}
                </p>
              </div>
              {getScanTypeIcon(progressData.scanType)}
            </div>
          </div>
          
          <div className="bg-gray-900/50 p-4 rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Status</p>
                <p className={`text-lg font-semibold capitalize ${
                  progressData.status === ScanStatus.COMPLETED ? 'text-green-400' : 
                  progressData.status === ScanStatus.RUNNING ? 'text-blue-400' : 'text-red-400'
                }`}>
                  {progressData.status}
                </p>
              </div>
              {getStatusIcon(progressData.status)}
            </div>
          </div>
        </div>
      </div>

      {/* Vulnerability Breakdown */}
      {progressData.vulnerabilitiesFound > 0 && (
        <div className="p-6 border-b border-gray-700">
          <h4 className="text-lg font-semibold mb-4">Vulnerability Breakdown</h4>
          <div className="grid grid-cols-5 gap-3">
            {[
              { severity: 'critical' as Severity, count: vulnerabilityCounts.critical, color: 'text-red-500' },
              { severity: 'high' as Severity, count: vulnerabilityCounts.high, color: 'text-orange-500' },
              { severity: 'medium' as Severity, count: vulnerabilityCounts.medium, color: 'text-yellow-500' },
              { severity: 'low' as Severity, count: vulnerabilityCounts.low, color: 'text-blue-500' },
              { severity: 'info' as Severity, count: vulnerabilityCounts.info, color: 'text-gray-500' }
            ].map(({ severity, count, color }) => (
              <div key={severity} className="text-center">
                <div className={`text-2xl font-bold ${color}`}>{count}</div>
                <div className="text-xs text-gray-400 capitalize">{severity}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Vulnerability List (if showing full report) */}
      {showFullReport && scanResult && scanResult.vulnerabilities.length > 0 && (
        <div className="p-6">
          <h4 className="text-lg font-semibold mb-4">Vulnerabilities Found</h4>
          <div className="space-y-3">
            {scanResult.vulnerabilities.map((vuln) => (
              <div key={vuln.id} className="bg-gray-900/50 p-4 rounded-lg border border-gray-700">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(vuln.severity)}`}>
                      {vuln.severity.toUpperCase()}
                    </span>
                    <h5 className="font-medium">{vuln.title}</h5>
                  </div>
                  <span className="text-xs text-gray-400">{vuln.confidence}% confidence</span>
                </div>
                <p className="text-sm text-gray-400 mb-2">{vuln.description}</p>
                <div className="flex items-center justify-between text-xs text-gray-500">
                  <span>Location: {vuln.location}</span>
                  <span>Type: {vuln.type}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Action Buttons */}
      <div className="p-6 bg-gray-900/30 flex justify-between items-center">
        <div className="flex space-x-2">
          <button
            onClick={() => window.open(`/reports/${scanId}`, '_blank')}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
          >
            <Eye className="h-4 w-4" />
            View Full Report
          </button>
          <button
            onClick={() => handleDownload('html')}
            className="px-4 py-2 bg-gray-600 hover:bg-gray-700 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
          >
            <FileText className="h-4 w-4" />
            Export HTML
          </button>
        </div>
        
        <p className="text-xs text-gray-500">
          Report generated on {new Date().toLocaleString()}
        </p>
      </div>
    </div>
  );
}
