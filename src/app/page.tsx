import Link from "next/link";
import { Shield, Scan, FileText, Activity } from "lucide-react";

export default function Home() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white">
      {/* Navigation */}
      <nav className="border-b border-gray-700 bg-gray-900/50 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16 items-center">
            <div className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-red-500" />
              <span className="text-xl font-bold">JagaScan</span>
            </div>
            <div className="hidden md:flex items-center space-x-8">
              <Link href="/dashboard" className="hover:text-red-400 transition-colors">
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

      {/* Hero Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        <div className="text-center">
          <h1 className="text-5xl md:text-6xl font-bold mb-6">
            <span className="text-red-500">Security</span> Scanner
          </h1>
          <p className="text-xl text-gray-300 mb-8 max-w-3xl mx-auto">
            Professional web-based penetration testing tool for identifying vulnerabilities 
            in web applications and networks. Secure your digital assets with automated scanning.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              href="/scan"
              className="bg-red-600 hover:bg-red-700 text-white px-8 py-3 rounded-lg font-semibold transition-colors flex items-center justify-center gap-2"
            >
              <Scan className="h-5 w-5" />
              Start Scanning
            </Link>
            <Link
              href="/dashboard"
              className="border border-gray-600 hover:border-red-500 text-white px-8 py-3 rounded-lg font-semibold transition-colors flex items-center justify-center gap-2"
            >
              <Activity className="h-5 w-5" />
              View Dashboard
            </Link>
          </div>
        </div>

        {/* Features Grid */}
        <div className="mt-20 grid md:grid-cols-3 gap-8">
          <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700">
            <div className="w-12 h-12 bg-red-600 rounded-lg flex items-center justify-center mb-4">
              <Scan className="h-6 w-6 text-white" />
            </div>
            <h3 className="text-xl font-semibold mb-2">Web Vulnerability Scanning</h3>
            <p className="text-gray-400">
              Detect SQL injection, XSS, CSRF, and other OWASP Top 10 vulnerabilities automatically.
            </p>
          </div>

          <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700">
            <div className="w-12 h-12 bg-red-600 rounded-lg flex items-center justify-center mb-4">
              <Activity className="h-6 w-6 text-white" />
            </div>
            <h3 className="text-xl font-semibold mb-2">Network Analysis</h3>
            <p className="text-gray-400">
              Port scanning, SSL/TLS analysis, and network service enumeration capabilities.
            </p>
          </div>

          <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700">
            <div className="w-12 h-12 bg-red-600 rounded-lg flex items-center justify-center mb-4">
              <FileText className="h-6 w-6 text-white" />
            </div>
            <h3 className="text-xl font-semibold mb-2">Detailed Reports</h3>
            <p className="text-gray-400">
              Generate comprehensive reports in PDF, HTML, and JSON formats with remediation advice.
            </p>
          </div>
        </div>

        {/* Security Notice */}
        <div className="mt-16 bg-yellow-900/20 border border-yellow-700 rounded-lg p-6">
          <div className="flex items-start space-x-3">
            <Shield className="h-6 w-6 text-yellow-500 mt-0.5" />
            <div>
              <h4 className="text-yellow-500 font-semibold mb-2">Security Notice</h4>
              <p className="text-gray-300">
                This tool is designed for authorized security testing only. 
                Ensure you have proper permission before scanning any targets. 
                Unauthorized scanning may violate laws and terms of service.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
