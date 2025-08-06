import { NextRequest, NextResponse } from 'next/server';
import { ApiResponse, ReportConfig, ReportFormat, ScanResult } from '@/types';
import { scannerService } from '@/lib/scannerService';

export async function POST(request: NextRequest): Promise<NextResponse<ApiResponse<{ reportUrl: string }>>> {
  try {
    const body: { scanId: string; config: ReportConfig } = await request.json();
    
    if (!body.scanId) {
      return NextResponse.json(
        { success: false, error: 'Scan ID is required' },
        { status: 400 }
      );
    }

    if (!body.config || !body.config.format) {
      return NextResponse.json(
        { success: false, error: 'Report configuration is required' },
        { status: 400 }
      );
    }

    // Mock report generation - replace with real implementation
    const reportUrl = await generateReport(body.scanId, body.config);

    return NextResponse.json({
      success: true,
      data: { reportUrl },
      message: 'Report generated successfully'
    });

  } catch (error) {
    console.error('Error generating report:', error);
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}

async function generateReport(scanId: string, config: ReportConfig): Promise<string> {
  // Mock report generation logic
  await new Promise(resolve => setTimeout(resolve, 2000)); // Simulate generation time
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const fileName = `scan-report-${scanId}-${timestamp}.${config.format}`;
  
  // In a real implementation, you would:
  // 1. Fetch scan data from database
  // 2. Generate report based on format (PDF, HTML, JSON, etc.)
  // 3. Save to file system or cloud storage
  // 4. Return the download URL
  
  return `/api/reports/download/${fileName}`;
}

export async function GET(request: NextRequest): Promise<NextResponse<ApiResponse<ScanResult[]>>> {
  try {
    console.log('📊 Reports API called');
    
    // Get query parameters for filtering
    const { searchParams } = new URL(request.url);
    const status = searchParams.get('status');
    const scanType = searchParams.get('scanType');
    const limit = searchParams.get('limit') ? parseInt(searchParams.get('limit')!) : undefined;
    const offset = searchParams.get('offset') ? parseInt(searchParams.get('offset')!) : undefined;

    const filters = {
      status: status as any,
      scanType: scanType as any,
      limit,
      offset
    };

    console.log('🔍 Fetching reports with filters:', filters);
    
    const reports = await scannerService.getAllScans(filters);
    
    console.log('✅ Found reports:', reports.length);

    return NextResponse.json({
      success: true,
      data: reports
    });

  } catch (error) {
    console.error('❌ Error fetching reports:', error);
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
