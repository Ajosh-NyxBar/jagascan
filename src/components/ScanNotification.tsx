'use client';

import { useState, useEffect } from 'react';
import { 
  CheckCircle, 
  AlertTriangle, 
  X, 
  Download, 
  Eye,
  Activity,
  Clock,
  Bug
} from 'lucide-react';
import { ScanStatus } from '@/types';

interface ScanNotificationProps {
  scanId: string;
  scanType: string;
  status: ScanStatus;
  vulnerabilitiesFound: number;
  duration: number;
  onDismiss: () => void;
  onViewReport: (scanId: string) => void;
  onDownload: (scanId: string) => void;
}

export default function ScanNotification({
  scanId,
  scanType,
  status,
  vulnerabilitiesFound,
  duration,
  onDismiss,
  onViewReport,
  onDownload
}: ScanNotificationProps) {
  const [isVisible, setIsVisible] = useState(false);
  const [isLeaving, setIsLeaving] = useState(false);

  useEffect(() => {
    // Animate in
    const timer = setTimeout(() => setIsVisible(true), 100);
    return () => clearTimeout(timer);
  }, []);

  const handleDismiss = () => {
    setIsLeaving(true);
    setTimeout(() => {
      onDismiss();
    }, 300);
  };

  const formatDuration = (milliseconds: number) => {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    
    if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  };

  const getStatusConfig = () => {
    switch (status) {
      case ScanStatus.COMPLETED:
        return {
          icon: CheckCircle,
          iconColor: 'text-green-400',
          bgColor: 'from-green-900/50 to-emerald-900/30',
          borderColor: 'border-green-500/30',
          title: 'Scan Completed Successfully!',
          message: `Found ${vulnerabilitiesFound} ${vulnerabilitiesFound === 1 ? 'vulnerability' : 'vulnerabilities'}`
        };
      case ScanStatus.FAILED:
        return {
          icon: AlertTriangle,
          iconColor: 'text-red-400',
          bgColor: 'from-red-900/50 to-red-900/30',
          borderColor: 'border-red-500/30',
          title: 'Scan Failed',
          message: 'An error occurred during scanning'
        };
      default:
        return {
          icon: Activity,
          iconColor: 'text-blue-400',
          bgColor: 'from-blue-900/50 to-blue-900/30',
          borderColor: 'border-blue-500/30',
          title: 'Scan In Progress',
          message: 'Your security scan is running...'
        };
    }
  };

  const config = getStatusConfig();
  const IconComponent = config.icon;

  return (
    <div
      className={`fixed top-4 right-4 z-50 max-w-md w-full transform transition-all duration-300 ${
        isVisible && !isLeaving
          ? 'translate-x-0 opacity-100'
          : 'translate-x-full opacity-0'
      }`}
    >
      <div className={`bg-gradient-to-r ${config.bgColor} backdrop-blur-sm border ${config.borderColor} rounded-lg shadow-2xl overflow-hidden`}>
        {/* Header */}
        <div className="p-4 border-b border-gray-700/50">
          <div className="flex items-start justify-between">
            <div className="flex items-center space-x-3">
              <div className="bg-gray-800/50 p-2 rounded-full">
                <IconComponent className={`h-5 w-5 ${config.iconColor}`} />
              </div>
              <div>
                <h4 className="font-semibold text-white">{config.title}</h4>
                <p className="text-sm text-gray-300">
                  {scanType.replace('_', ' ')} scan
                </p>
              </div>
            </div>
            <button
              onClick={handleDismiss}
              className="text-gray-400 hover:text-white transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-4">
          <div className="flex items-center justify-between mb-3">
            <p className="text-sm text-gray-300">{config.message}</p>
            <span className="text-xs text-gray-400">
              ID: {scanId.slice(0, 8)}...
            </span>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 gap-3 mb-4">
            <div className="bg-gray-800/30 p-2 rounded">
              <div className="flex items-center space-x-2">
                <Clock className="h-4 w-4 text-gray-400" />
                <div>
                  <p className="text-xs text-gray-400">Duration</p>
                  <p className="text-sm font-medium text-white">
                    {formatDuration(duration)}
                  </p>
                </div>
              </div>
            </div>
            
            {status === ScanStatus.COMPLETED && (
              <div className="bg-gray-800/30 p-2 rounded">
                <div className="flex items-center space-x-2">
                  <Bug className="h-4 w-4 text-red-400" />
                  <div>
                    <p className="text-xs text-gray-400">Issues</p>
                    <p className="text-sm font-medium text-red-400">
                      {vulnerabilitiesFound}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Action Buttons */}
          {status === ScanStatus.COMPLETED && (
            <div className="flex space-x-2">
              <button
                onClick={() => onViewReport(scanId)}
                className="flex-1 bg-blue-600 hover:bg-blue-700 px-3 py-2 rounded text-sm font-medium transition-colors flex items-center justify-center gap-2"
              >
                <Eye className="h-4 w-4" />
                View Report
              </button>
              <button
                onClick={() => onDownload(scanId)}
                className="bg-green-600 hover:bg-green-700 px-3 py-2 rounded text-sm font-medium transition-colors flex items-center gap-1"
              >
                <Download className="h-4 w-4" />
                PDF
              </button>
            </div>
          )}
        </div>

        {/* Progress indicator for running scans */}
        {status === ScanStatus.RUNNING && (
          <div className="h-1 bg-gray-700">
            <div className="h-full bg-blue-500 animate-pulse w-2/3"></div>
          </div>
        )}
      </div>
    </div>
  );
}
