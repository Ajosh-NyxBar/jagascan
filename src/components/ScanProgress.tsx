'use client';

import { useState, useEffect } from 'react';
import { Clock, Activity, CheckCircle, AlertTriangle } from 'lucide-react';
import { ScanStatus, ScanType } from '@/types';

interface ScanProgressProps {
  scanId: string;
  onComplete?: (scanId: string) => void;
  onError?: (error: string) => void;
}

interface ScanProgressData {
  status: ScanStatus;
  progress: number;
  currentTask: string;
  vulnerabilitiesFound: number;
  elapsed: number;
  scanType: ScanType;
}

export default function ScanProgress({ scanId, onComplete, onError }: ScanProgressProps) {
  const [progressData, setProgressData] = useState<ScanProgressData>({
    status: ScanStatus.PENDING,
    progress: 0,
    currentTask: 'Initializing scan...',
    vulnerabilitiesFound: 0,
    elapsed: 0,
    scanType: ScanType.WEB_VULNERABILITY
  });

  useEffect(() => {
    let interval: NodeJS.Timeout;

    const pollProgress = async () => {
      try {
        // Mock progress polling - replace with real API call
        const response = await fetch(`/api/scan/${scanId}/progress`);
        if (!response.ok) throw new Error('Failed to fetch progress');
        
        const data = await response.json();
        setProgressData(data);

        if (data.status === ScanStatus.COMPLETED && onComplete) {
          onComplete(scanId);
        } else if (data.status === ScanStatus.FAILED && onError) {
          onError('Scan failed');
        }
      } catch (error) {
        console.error('Error polling progress:', error);
        // Mock progress for demo
        setProgressData(prev => {
          const newProgress = Math.min(prev.progress + Math.random() * 10, 100);
          const newStatus = newProgress >= 100 ? ScanStatus.COMPLETED : ScanStatus.RUNNING;
          
          return {
            ...prev,
            status: newStatus,
            progress: newProgress,
            currentTask: getTaskForProgress(newProgress),
            vulnerabilitiesFound: Math.floor(newProgress / 20),
            elapsed: prev.elapsed + 1000
          };
        });
      }
    };

    // Start polling
    interval = setInterval(pollProgress, 1000);
    pollProgress(); // Initial call

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [scanId, onComplete, onError]);

  const getTaskForProgress = (progress: number): string => {
    if (progress < 20) return 'Initializing scan...';
    if (progress < 40) return 'Crawling target...';
    if (progress < 60) return 'Testing for vulnerabilities...';
    if (progress < 80) return 'Analyzing results...';
    if (progress < 100) return 'Generating report...';
    return 'Scan completed';
  };

  const formatElapsed = (milliseconds: number): string => {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    return `${minutes}:${(seconds % 60).toString().padStart(2, '0')}`;
  };

  const getStatusIcon = () => {
    switch (progressData.status) {
      case ScanStatus.RUNNING:
        return <Activity className="h-5 w-5 text-blue-500 animate-pulse" />;
      case ScanStatus.COMPLETED:
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case ScanStatus.FAILED:
        return <AlertTriangle className="h-5 w-5 text-red-500" />;
      default:
        return <Clock className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusColor = () => {
    switch (progressData.status) {
      case ScanStatus.RUNNING:
        return 'text-blue-500';
      case ScanStatus.COMPLETED:
        return 'text-green-500';
      case ScanStatus.FAILED:
        return 'text-red-500';
      default:
        return 'text-gray-500';
    }
  };

  return (
    <div className="bg-gray-800/50 rounded-lg border border-gray-700 p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-3">
          {getStatusIcon()}
          <div>
            <h3 className="text-lg font-semibold">Scan Progress</h3>
            <p className="text-sm text-gray-400">Scan ID: {scanId}</p>
          </div>
        </div>
        <div className="text-right">
          <p className={`font-medium ${getStatusColor()}`}>
            {progressData.status.toUpperCase()}
          </p>
          <p className="text-sm text-gray-400">
            <Clock className="h-4 w-4 inline mr-1" />
            {formatElapsed(progressData.elapsed)}
          </p>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="mb-4">
        <div className="flex justify-between text-sm mb-2">
          <span className="text-gray-400">{progressData.currentTask}</span>
          <span className="text-gray-400">{Math.round(progressData.progress)}%</span>
        </div>
        <div className="w-full bg-gray-700 rounded-full h-2">
          <div
            className="bg-red-500 h-2 rounded-full transition-all duration-300 ease-out"
            style={{ width: `${progressData.progress}%` }}
          ></div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <p className="text-sm text-gray-400">Vulnerabilities Found</p>
          <p className="text-xl font-bold text-red-400">{progressData.vulnerabilitiesFound}</p>
        </div>
        <div>
          <p className="text-sm text-gray-400">Scan Type</p>
          <p className="text-sm font-medium capitalize">
            {progressData.scanType.replace('_', ' ')}
          </p>
        </div>
      </div>

      {/* Action Buttons */}
      {progressData.status === ScanStatus.RUNNING && (
        <div className="mt-4 flex space-x-2">
          <button
            onClick={() => {
              // Mock cancel functionality
              setProgressData(prev => ({ ...prev, status: ScanStatus.CANCELLED }));
            }}
            className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg text-sm font-medium transition-colors"
          >
            Cancel Scan
          </button>
        </div>
      )}

      {progressData.status === ScanStatus.COMPLETED && (
        <div className="mt-4 flex space-x-2">
          <button
            onClick={() => window.open(`/api/reports/${scanId}`, '_blank')}
            className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm font-medium transition-colors"
          >
            View Report
          </button>
          <button
            onClick={() => window.open(`/api/reports/${scanId}/download`, '_blank')}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"
          >
            Download PDF
          </button>
        </div>
      )}
    </div>
  );
}
