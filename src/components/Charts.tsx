'use client';

import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Severity } from '@/types';

interface VulnerabilityChartProps {
  data: {
    severity: Severity;
    count: number;
  }[];
}

interface ScanActivityChartProps {
  data: {
    date: string;
    scans: number;
    vulnerabilities: number;
  }[];
}

const SEVERITY_COLORS = {
  [Severity.CRITICAL]: '#DC2626',
  [Severity.HIGH]: '#EA580C',
  [Severity.MEDIUM]: '#CA8A04',
  [Severity.LOW]: '#2563EB',
  [Severity.INFO]: '#6B7280'
};

export function VulnerabilityDistributionChart({ data }: VulnerabilityChartProps) {
  const chartData = data.map(item => ({
    name: item.severity.toUpperCase(),
    value: item.count,
    color: SEVERITY_COLORS[item.severity]
  }));

  const total = data.reduce((sum, item) => sum + item.count, 0);

  return (
    <div className="bg-gray-800/50 rounded-lg border border-gray-700 p-6">
      <h3 className="text-lg font-semibold mb-4">Vulnerability Distribution</h3>
      <div className="flex items-center space-x-6">
        <div className="flex-1">
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                outerRadius={80}
                dataKey="value"
                label={({ name, percent }) => `${name} ${((percent || 0) * 100).toFixed(0)}%`}
              >
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
        
        <div className="flex-1 space-y-3">
          <div className="text-center mb-4">
            <p className="text-2xl font-bold">{total}</p>
            <p className="text-sm text-gray-400">Total Vulnerabilities</p>
          </div>
          
          {data.map((item) => (
            <div key={item.severity} className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: SEVERITY_COLORS[item.severity] }}
                ></div>
                <span className="text-sm capitalize">{item.severity}</span>
              </div>
              <span className="text-sm font-medium">{item.count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function ScanActivityChart({ data }: ScanActivityChartProps) {
  return (
    <div className="bg-gray-800/50 rounded-lg border border-gray-700 p-6">
      <h3 className="text-lg font-semibold mb-4">Scan Activity (Last 7 Days)</h3>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis 
            dataKey="date" 
            stroke="#9CA3AF"
            fontSize={12}
          />
          <YAxis stroke="#9CA3AF" fontSize={12} />
          <Tooltip 
            contentStyle={{
              backgroundColor: '#1F2937',
              border: '1px solid #374151',
              borderRadius: '8px',
              color: '#F3F4F6'
            }}
          />
          <Bar dataKey="scans" fill="#EF4444" name="Scans" />
          <Bar dataKey="vulnerabilities" fill="#F59E0B" name="Vulnerabilities" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
