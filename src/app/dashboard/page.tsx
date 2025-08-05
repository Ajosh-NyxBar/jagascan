'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { 
  Shield, 
  BarChart3, 
  Activity, 
  AlertTriangle, 
  Play, 
  FileText, 
  Target,
  CheckCircle,
  Clock,
  TrendingUp,
  Users,
  Globe
} from 'lucide-react';

interface DashboardStats {
  totalScans: number;
  activeScans: number;
  vulnerabilitiesFound: number;
  criticalVulnerabilities: number;
  recentScans: Array<{
    id: string;
    status: 'completed' | 'running' | 'failed';
    startTime: Date;
    vulnerabilities: any[];
    metadata: {
      duration: number;
    };
  }>;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await fetch('/api/dashboard/stats');
        if (response.ok) {
          const data = await response.json();
          setStats(data);
        }
      } catch (error) {
        console.error('Failed to fetch dashboard stats:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    
    // Auto refresh every 30 seconds
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500 mx-auto mb-4"></div>
          <p className="text-gray-400">Loading dashboard...</p>
        </div>
      </div>
    );
  }

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
              <Link href="/dashboard" className="text-red-400 border-b-2 border-red-400 pb-1">
                Dashboard
              </Link>
              <Link href="/scan" className="hover:text-red-400 transition-colors">
                New Scan
              </Link>
              <Link href="/reports" className="hover:text-red-400 transition-colors">
                Reports
              </Link>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">Security Dashboard</h1>
          <p className="text-gray-400">Monitor your security scanning activities and vulnerabilities</p>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Total Scans</p>
                <p className="text-2xl font-bold">{stats?.totalScans || 0}</p>
                <p className="text-xs text-green-400 mt-1">
                  <TrendingUp className="h-3 w-3 inline mr-1" />
                  +12% from last week
                </p>
              </div>
              <BarChart3 className="h-8 w-8 text-blue-500" />
            </div>
          </div>

          <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Active Scans</p>
                <p className="text-2xl font-bold">{stats?.activeScans || 0}</p>
                <p className="text-xs text-yellow-400 mt-1">
                  <Activity className="h-3 w-3 inline mr-1" />
                  Currently running
                </p>
              </div>
              <Activity className="h-8 w-8 text-green-500" />
            </div>
          </div>

          <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Vulnerabilities</p>
                <p className="text-2xl font-bold">{stats?.vulnerabilitiesFound || 0}</p>
                <p className="text-xs text-blue-400 mt-1">
                  <Globe className="h-3 w-3 inline mr-1" />
                  All severities
                </p>
              </div>
              <AlertTriangle className="h-8 w-8 text-yellow-500" />
            </div>
          </div>

          <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Critical Issues</p>
                <p className="text-2xl font-bold text-red-500">{stats?.criticalVulnerabilities || 0}</p>
                <p className="text-xs text-red-400 mt-1">
                  <AlertTriangle className="h-3 w-3 inline mr-1" />
                  Requires attention
                </p>
              </div>
              <AlertTriangle className="h-8 w-8 text-red-500" />
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <Link
            href="/scan"
            className="bg-gradient-to-br from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 p-6 rounded-lg transition-all duration-300 transform hover:scale-105 group"
          >
            <div className="flex items-center space-x-3">
              <Play className="h-8 w-8 group-hover:scale-110 transition-transform" />
              <div>
                <h3 className="text-lg font-semibold">Start New Scan</h3>
                <p className="text-red-100">Begin vulnerability assessment</p>
              </div>
            </div>
          </Link>

          <Link
            href="/reports"
            className="bg-gray-800/50 hover:bg-gray-700/50 p-6 rounded-lg border border-gray-700 hover:border-gray-600 transition-all duration-300 transform hover:scale-105 group"
          >
            <div className="flex items-center space-x-3">
              <FileText className="h-8 w-8 text-blue-400 group-hover:scale-110 transition-transform" />
              <div>
                <h3 className="text-lg font-semibold">View Reports</h3>
                <p className="text-gray-400">Access scan reports</p>
              </div>
            </div>
          </Link>

          <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700 hover:border-gray-600 transition-all duration-300 transform hover:scale-105 group cursor-pointer">
            <div className="flex items-center space-x-3">
              <Target className="h-8 w-8 text-purple-400 group-hover:scale-110 transition-transform" />
              <div>
                <h3 className="text-lg font-semibold">Scan History</h3>
                <p className="text-gray-400">Review past scans</p>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Scans Section */}
        <div className="bg-gray-800/50 rounded-lg border border-gray-700 p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold">Recent Scans</h2>
            <Link 
              href="/reports" 
              className="text-red-400 hover:text-red-300 text-sm font-medium transition-colors"
            >
              View All →
            </Link>
          </div>
          
          <div className="space-y-4">
            {stats?.recentScans?.length ? (
              stats.recentScans.map((scan) => (
                <div key={scan.id} className="flex items-center justify-between p-4 bg-gray-700/30 rounded-lg hover:bg-gray-700/50 transition-colors">
                  <div className="flex items-center space-x-4">
                    <div className="flex-shrink-0">
                      {scan.status === 'completed' ? (
                        <CheckCircle className="h-6 w-6 text-green-500" />
                      ) : scan.status === 'running' ? (
                        <Clock className="h-6 w-6 text-yellow-500 animate-pulse" />
                      ) : (
                        <AlertTriangle className="h-6 w-6 text-red-500" />
                      )}
                    </div>
                    <div>
                      <p className="font-medium">Web Vulnerability Scan</p>
                      <p className="text-sm text-gray-400">
                        Started: {new Date(scan.startTime).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="font-medium">{scan.vulnerabilities?.length || 0} vulnerabilities</p>
                    <p className="text-sm text-gray-400">
                      Duration: {Math.round((scan.metadata?.duration || 0) / 60000)}m
                    </p>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-12">
                <Activity className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium mb-2">No recent scans</h3>
                <p className="text-gray-400 mb-4">Start your first security scan to see results here</p>
                <Link
                  href="/scan"
                  className="bg-red-600 hover:bg-red-700 px-6 py-2 rounded-lg font-medium transition-colors inline-flex items-center gap-2"
                >
                  <Play className="h-4 w-4" />
                  Start New Scan
                </Link>
              </div>
            )}
          </div>
        </div>

        {/* Security Tips */}
        <div className="mt-8 bg-blue-900/20 border border-blue-700 rounded-lg p-6">
            <div className="flex items-start space-x-3">
            <Shield className="h-6 w-6 text-blue-400 mt-0.5" />
            <div>
              <h3 className="text-blue-400 font-semibold mb-2">Security Tip</h3>
              <p className="text-gray-300 text-sm">
              Regular security scanning helps identify vulnerabilities before they can be exploited.
              Schedule weekly scans for critical assets and monitor for new threats continuously.
              </p>
            </div>
            </div>
        </div>
      </div>
    </div>
  );
}
