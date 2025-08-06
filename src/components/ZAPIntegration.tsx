import React, { useState, useEffect } from 'react';
import { Shield, Settings, CheckCircle, XCircle, AlertTriangle, Play, Loader2 } from 'lucide-react';

interface ZAPConfig {
  zapEnabled: boolean;
  zapUrl: string;
  apiKey: string;
  spiderMaxDepth: number;
  spiderMaxChildren: number;
  enableActiveScan: boolean;
  enablePassiveScan: boolean;
}

interface ZAPStatus {
  connected: boolean;
  version?: string;
  error?: string;
}

interface ZAPIntegrationProps {
  onConfigChange: (config: ZAPConfig) => void;
  onStartZAPScan: (config: ZAPConfig) => void;
  isScanning?: boolean;
}

const ZAPIntegration: React.FC<ZAPIntegrationProps> = ({
  onConfigChange,
  onStartZAPScan,
  isScanning = false
}) => {
  const [config, setConfig] = useState<ZAPConfig>({
    zapEnabled: false,
    zapUrl: 'http://localhost:8080',
    apiKey: 'akbar12',
    spiderMaxDepth: 5,  
    spiderMaxChildren: 10,
    enableActiveScan: true,
    enablePassiveScan: true
  });

  const [status, setStatus] = useState<ZAPStatus>({
    connected: false
  });

  const [testing, setTesting] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  useEffect(() => {
    // Test connection when ZAP is enabled
    if (config.zapEnabled) {
      testZAPConnection();
    }
  }, [config.zapEnabled, config.zapUrl, config.apiKey]);

  useEffect(() => {
    onConfigChange(config);
  }, [config, onConfigChange]);

  const testZAPConnection = async () => {
    setTesting(true);
    try {
      const response = await fetch(`/api/zap/status?zapUrl=${encodeURIComponent(config.zapUrl)}&apiKey=${encodeURIComponent(config.apiKey)}`);
      const result = await response.json();
      
      if (result.success) {
        setStatus({
          connected: true,
          version: result.data.version
        });
      } else {
        setStatus({
          connected: false,
          error: result.error
        });
      }
    } catch (error) {
      setStatus({
        connected: false,
        error: 'Failed to connect to ZAP'
      });
    } finally {
      setTesting(false);
    }
  };

  const handleConfigChange = (updates: Partial<ZAPConfig>) => {
    setConfig(prev => ({ ...prev, ...updates }));
  };

  const handleStartScan = () => {
    if (status.connected) {
      onStartZAPScan(config);
    }
  };

  return (
    <div className="space-y-6">
      {/* Enable/Disable Toggle */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <Shield className="h-6 w-6 text-purple-500" />
          <div>
            <h3 className="text-lg font-semibold">OWASP ZAP Integration</h3>
            <p className="text-sm text-gray-400">Professional security scanning with ZAP</p>
          </div>
        </div>
        <label className="flex items-center space-x-3">
          <span className="text-sm font-medium">Enable ZAP</span>
          <input
            type="checkbox"
            checked={config.zapEnabled}
            onChange={(e) => handleConfigChange({ zapEnabled: e.target.checked })}
            className="w-4 h-4 text-purple-600 bg-gray-700 border-gray-600 rounded focus:ring-purple-500"
          />
        </label>
      </div>

      {config.zapEnabled && (
        <>
          {/* Connection Status */}
          <div className="bg-gray-700/30 rounded-lg p-4">
            <div className="flex items-center justify-between mb-4">
              <h4 className="font-semibold">Connection Status</h4>
              <button
                onClick={testZAPConnection}
                disabled={testing}
                className="flex items-center gap-2 px-3 py-1 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 text-white text-sm rounded"
              >
                {testing ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Testing...
                  </>
                ) : (
                  'Test Connection'
                )}
              </button>
            </div>
            
            <div className="flex items-center gap-3">
              {testing ? (
                <Loader2 className="w-5 h-5 animate-spin text-blue-500" />
              ) : status.connected ? (
                <CheckCircle className="w-5 h-5 text-green-500" />
              ) : (
                <XCircle className="w-5 h-5 text-red-500" />
              )}
              
              <div>
                <p className={`font-medium ${status.connected ? 'text-green-400' : 'text-red-400'}`}>
                  {testing ? 'Testing connection...' : 
                   status.connected ? 'Connected to ZAP' : 'Connection failed'}
                </p>
                {status.version && (
                  <p className="text-sm text-gray-400">ZAP Version: {status.version}</p>
                )}
                {status.error && (
                  <p className="text-sm text-red-400">{status.error}</p>
                )}
              </div>
            </div>
          </div>

          {/* Basic Configuration */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">ZAP URL</label>
              <input
                type="text"
                value={config.zapUrl}
                onChange={(e) => handleConfigChange({ zapUrl: e.target.value })}
                placeholder="http://localhost:8080"
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-2">API Key</label>
              <input
                type="password"
                value={config.apiKey}
                onChange={(e) => handleConfigChange({ apiKey: e.target.value })}
                placeholder="Enter ZAP API key"
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
              />
            </div>
          </div>

          {/* Advanced Settings */}
          <div>
            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex items-center gap-2 text-sm font-medium text-purple-400 hover:text-purple-300"
            >
              <Settings className={`w-4 h-4 transition-transform ${showAdvanced ? 'rotate-90' : ''}`} />
              Advanced Settings
            </button>

            {showAdvanced && (
              <div className="mt-4 space-y-4 p-4 bg-gray-700/20 rounded-lg">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-2">Spider Max Depth</label>
                    <input
                      type="number"
                      value={config.spiderMaxDepth}
                      onChange={(e) => handleConfigChange({ spiderMaxDepth: parseInt(e.target.value) })}
                      min="1"
                      max="10"
                      className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg"
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium mb-2">Spider Max Children</label>
                    <input
                      type="number"
                      value={config.spiderMaxChildren}
                      onChange={(e) => handleConfigChange({ spiderMaxChildren: parseInt(e.target.value) })}
                      min="1"
                      max="50"
                      className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg"
                    />
                  </div>
                </div>

                <div className="space-y-3">
                  <label className="flex items-center space-x-3">
                    <input
                      type="checkbox"
                      checked={config.enablePassiveScan}
                      onChange={(e) => handleConfigChange({ enablePassiveScan: e.target.checked })}
                      className="w-4 h-4 text-purple-600 bg-gray-700 border-gray-600 rounded focus:ring-purple-500"
                    />
                    <span className="text-sm">Enable Passive Scanning (Spider)</span>
                  </label>
                  
                  <label className="flex items-center space-x-3">
                    <input
                      type="checkbox"
                      checked={config.enableActiveScan}
                      onChange={(e) => handleConfigChange({ enableActiveScan: e.target.checked })}
                      className="w-4 h-4 text-purple-600 bg-gray-700 border-gray-600 rounded focus:ring-purple-500"
                    />
                    <span className="text-sm">Enable Active Scanning (Vulnerability Testing)</span>
                  </label>
                </div>
              </div>
            )}
          </div>

          {/* Setup Instructions */}
          {!status.connected && (
            <div className="bg-yellow-900/20 border border-yellow-700 rounded-lg p-4">
              <div className="flex items-start space-x-3">
                <AlertTriangle className="h-5 w-5 text-yellow-500 mt-0.5" />
                <div>
                  <h4 className="text-yellow-500 font-semibold mb-2">ZAP Setup Required</h4>
                  <div className="text-sm text-gray-300 space-y-1">
                    <p>1. Start OWASP ZAP application</p>
                    <p>2. Go to Tools → Options → API</p>
                    <p>3. Enable API and set API Key: <code className="bg-gray-700 px-1 rounded">akbar12</code></p>
                    <p>4. Ensure ZAP is running on: <code className="bg-gray-700 px-1 rounded">{config.zapUrl}</code></p>
                    <p>5. Click "Test Connection" above</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Start ZAP Scan Button */}
          {status.connected && (
            <button
              onClick={handleStartScan}
              disabled={isScanning}
              className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white px-6 py-3 rounded-lg font-semibold transition-colors flex items-center justify-center gap-2"
            >
              {isScanning ? (
                <>
                  <Loader2 className="h-5 w-5 animate-spin" />
                  ZAP Scan Running...
                </>
              ) : (
                <>
                  <Play className="h-5 w-5" />
                  Start ZAP-Enhanced Scan
                </>
              )}
            </button>
          )}
        </>
      )}
    </div>
  );
};

export default ZAPIntegration;
