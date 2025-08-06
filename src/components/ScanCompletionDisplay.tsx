'use client';

import { useState, useEffect } from 'react';
import { 
  CheckCircle, 
  AlertTriangle, 
  Clock, 
  Bug, 
  Download, 
  Eye,
  Share2,
  X,
  Zap,
  Shield,
  TrendingUp
} from 'lucide-react';

interface ScanCompletionData {
  status: 'completed' | 'failed';
  progress: number;
  currentTask: string;
  vulnerabilitiesFound: number;
  elapsed: number;
  scanType: string;
  scanId?: string;
}

interface ScanCompletionDisplayProps {
  data: ScanCompletionData;
  onViewReport?: (scanId: string) => void;
  onDownload?: (scanId: string) => void;
  onDismiss?: () => void;
  showActions?: boolean;
}

export default function ScanCompletionDisplay({
  data,
  onViewReport,
  onDownload,
  onDismiss,
  showActions = true
}: ScanCompletionDisplayProps) {
  const [isVisible, setIsVisible] = useState(false);
  const [showDetails, setShowDetails] = useState(false);

  useEffect(() => {
    // Animate in after a short delay
    const timer = setTimeout(() => setIsVisible(true), 200);
    return () => clearTimeout(timer);
  }, []);

  const formatDuration = (milliseconds: number) => {
    const totalSeconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    
    if (minutes > 0) {
      return `${minutes}m ${seconds}s`;
    } else {
      return `${seconds}s`;
    }
  };

  const getSeverityLevel = (vulnCount: number) => {
    if (vulnCount === 0) return { level: 'Safe', color: 'text-green-400', bgColor: 'bg-green-500/10' };
    if (vulnCount <= 5) return { level: 'Low Risk', color: 'text-yellow-400', bgColor: 'bg-yellow-500/10' };
    if (vulnCount <= 15) return { level: 'Medium Risk', color: 'text-orange-400', bgColor: 'bg-orange-500/10' };
    return { level: 'High Risk', color: 'text-red-400', bgColor: 'bg-red-500/10' };
  };

  const getStatusConfig = () => {
    if (data.status === 'completed') {
      const severity = getSeverityLevel(data.vulnerabilitiesFound);
      return {
        icon: CheckCircle,
        iconColor: data.vulnerabilitiesFound === 0 ? 'text-green-400' : 'text-orange-400',
        bgGradient: data.vulnerabilitiesFound === 0 
          ? 'from-green-900/30 via-emerald-900/20 to-green-900/10'
          : 'from-orange-900/30 via-red-900/20 to-orange-900/10',
        borderColor: data.vulnerabilitiesFound === 0 ? 'border-green-500/30' : 'border-orange-500/30',
        title: data.vulnerabilitiesFound === 0 ? 'Scan Completed - No Issues Found!' : 'Scan Completed - Issues Detected',
        subtitle: data.vulnerabilitiesFound === 0 
          ? 'Your target appears to be secure' 
          : `${data.vulnerabilitiesFound} security issues require attention`,
        severity
      };
    } else {
      return {
        icon: AlertTriangle,
        iconColor: 'text-red-400',
        bgGradient: 'from-red-900/30 via-red-800/20 to-red-900/10',
        borderColor: 'border-red-500/30',
        title: 'Scan Failed',
        subtitle: 'An error occurred during the security scan',
        severity: { level: 'Error', color: 'text-red-400', bgColor: 'bg-red-500/10' }
      };
    }
  };

  const config = getStatusConfig();
  const IconComponent = config.icon;

  const handleDismiss = () => {
    setIsVisible(false);
    setTimeout(() => {
      onDismiss?.();
    }, 300);
  };

  return (
    <div
      className={`fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4 transition-all duration-300 ${
        isVisible ? 'opacity-100' : 'opacity-0 pointer-events-none'
      }`}
    >
      <div
        className={`max-w-2xl w-full transform transition-all duration-500 ${
          isVisible ? 'scale-100 translate-y-0' : 'scale-95 translate-y-8'
        }`}
      >
        <div className={`bg-gradient-to-br ${config.bgGradient} backdrop-blur-xl border ${config.borderColor} rounded-2xl shadow-2xl overflow-hidden`}>
          {/* Header */}
          <div className="relative p-6 pb-4">
            {onDismiss && (
              <button
                onClick={handleDismiss}
                className="absolute top-4 right-4 text-gray-400 hover:text-white transition-colors z-10"
              >
                <X className="h-6 w-6" />
              </button>
            )}
            
            <div className="flex items-start space-x-4">
              <div className="bg-gray-800/50 p-4 rounded-2xl">
                <IconComponent className={`h-12 w-12 ${config.iconColor}`} />
              </div>
              
              <div className="flex-1">
                <h2 className="text-2xl font-bold text-white mb-2">
                  {config.title}
                </h2>
                <p className="text-gray-300 mb-4">
                  {config.subtitle}
                </p>
                
                {/* Severity Badge */}
                <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${config.severity.bgColor} ${config.severity.color} border border-current/20`}>
                  <Shield className="h-4 w-4 mr-2" />
                  {config.severity.level}
                </div>
              </div>
            </div>
          </div>

          {/* Stats Grid */}
          <div className="px-6 pb-4">
            <div className="grid grid-cols-3 gap-4">
              {/* Duration */}
              <div className="bg-gray-800/30 p-4 rounded-xl">
                <div className="flex items-center space-x-2 mb-2">
                  <Clock className="h-5 w-5 text-blue-400" />
                  <span className="text-sm text-gray-400">Duration</span>
                </div>
                <p className="text-xl font-bold text-white">
                  {formatDuration(data.elapsed)}
                </p>
              </div>

              {/* Vulnerabilities */}
              <div className="bg-gray-800/30 p-4 rounded-xl">
                <div className="flex items-center space-x-2 mb-2">
                  <Bug className="h-5 w-5 text-red-400" />
                  <span className="text-sm text-gray-400">Issues Found</span>
                </div>
                <p className={`text-xl font-bold ${data.vulnerabilitiesFound === 0 ? 'text-green-400' : 'text-red-400'}`}>
                  {data.vulnerabilitiesFound}
                </p>
              </div>

              {/* Scan Type */}
              <div className="bg-gray-800/30 p-4 rounded-xl">
                <div className="flex items-center space-x-2 mb-2">
                  <Zap className="h-5 w-5 text-purple-400" />
                  <span className="text-sm text-gray-400">Scan Type</span>
                </div>
                <p className="text-sm font-bold text-white capitalize">
                  {data.scanType.replace('_', ' ')}
                </p>
              </div>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="px-6 pb-4">
            <div className="bg-gray-800/30 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-400">Progress</span>
                <span className="text-sm font-medium text-white">{data.progress}%</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-3">
                <div
                  className="bg-gradient-to-r from-green-500 to-emerald-500 h-3 rounded-full transition-all duration-1000 ease-out flex items-center justify-end pr-1"
                  style={{ width: `${data.progress}%` }}
                >
                  {data.progress === 100 && (
                    <CheckCircle className="h-2 w-2 text-white" />
                  )}
                </div>
              </div>
              <p className="text-xs text-gray-400 mt-2">{data.currentTask}</p>
            </div>
          </div>

          {/* Detailed Info (Expandable) */}
          <div className="px-6 pb-4">
            <button
              onClick={() => setShowDetails(!showDetails)}
              className="w-full bg-gray-800/30 hover:bg-gray-800/50 p-3 rounded-xl transition-colors flex items-center justify-between"
            >
              <span className="text-sm font-medium text-gray-300">
                {showDetails ? 'Hide Details' : 'Show Details'}
              </span>
              <TrendingUp className={`h-4 w-4 text-gray-400 transition-transform ${showDetails ? 'rotate-180' : ''}`} />
            </button>
            
            {showDetails && (
              <div className="mt-4 space-y-3 animate-in slide-in-from-top-2 duration-200">
                <div className="bg-gray-800/20 p-3 rounded-lg">
                  <h4 className="text-sm font-medium text-white mb-2">Scan Summary</h4>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-gray-400">Status:</span>
                      <span className="ml-2 text-white capitalize">{data.status}</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Progress:</span>
                      <span className="ml-2 text-white">{data.progress}%</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Current Task:</span>
                      <span className="ml-2 text-white">{data.currentTask}</span>
                    </div>
                    <div>
                      <span className="text-gray-400">Elapsed Time:</span>
                      <span className="ml-2 text-white">{formatDuration(data.elapsed)}</span>
                    </div>
                  </div>
                </div>
                
                {data.vulnerabilitiesFound > 0 && (
                  <div className="bg-red-900/20 border border-red-500/30 p-3 rounded-lg">
                    <p className="text-sm text-red-200">
                      <AlertTriangle className="h-4 w-4 inline mr-2" />
                      Security issues detected that require immediate attention.
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Action Buttons */}
          {showActions && data.status === 'completed' && data.scanId && (
            <div className="px-6 pb-6">
              <div className="flex space-x-3">
                <button
                  onClick={() => onViewReport?.(data.scanId!)}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 px-4 py-3 rounded-xl font-medium transition-colors flex items-center justify-center gap-2 text-white"
                >
                  <Eye className="h-5 w-5" />
                  View Detailed Report
                </button>
                <button
                  onClick={() => onDownload?.(data.scanId!)}
                  className="bg-green-600 hover:bg-green-700 px-4 py-3 rounded-xl font-medium transition-colors flex items-center gap-2 text-white"
                >
                  <Download className="h-5 w-5" />
                  PDF
                </button>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(`Scan completed: ${data.vulnerabilitiesFound} issues found in ${formatDuration(data.elapsed)}`);
                  }}
                  className="bg-gray-600 hover:bg-gray-700 px-4 py-3 rounded-xl font-medium transition-colors flex items-center gap-2 text-white"
                >
                  <Share2 className="h-5 w-5" />
                </button>
              </div>
            </div>
          )}
          
          {/* Footer Message */}
          {data.status === 'completed' && (
            <div className="bg-gray-800/20 px-6 py-3">
              <p className="text-xs text-gray-400 text-center">
                {data.vulnerabilitiesFound === 0 
                  ? '🎉 Congratulations! No security vulnerabilities were detected.' 
                  : '⚠️ Please review the security issues and take appropriate action.'}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
