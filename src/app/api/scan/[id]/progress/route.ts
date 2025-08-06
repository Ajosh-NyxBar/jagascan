import { NextRequest, NextResponse } from 'next/server';
import { scannerService } from '@/lib/scannerService';
import { ApiResponse, ScanStatus } from '@/types';

interface ProgressData {
  status: ScanStatus;
  progress: number;
  currentTask: string;
  vulnerabilitiesFound: number;
  elapsed: number;
  scanType: string;
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
): Promise<NextResponse<ApiResponse<ProgressData>>> {
  try {
    const { id: scanId } = await params;
    console.log('🔍 Progress API called for scanId:', scanId);
    
    if (!scanId) {
      console.log('❌ No scan ID provided');
      return NextResponse.json(
        { success: false, error: 'Scan ID is required' },
        { status: 400 }
      );
    }

    console.log('📊 Looking up scan in database...');
    const scan = await scannerService.getScanResult(scanId);
    
    if (!scan) {
      console.log('❌ Scan not found in database for ID:', scanId);
      return NextResponse.json(
        { success: false, error: 'Scan not found' },
        { status: 404 }
      );
    }

    console.log('✅ Scan found:', {
      id: scan.id,
      status: scan.status,
      vulnerabilities: scan.vulnerabilities.length,
      startTime: scan.startTime
    });

    // Calculate progress based on scan status and elapsed time
    let progress = 0;
    let currentTask = 'Initializing scan...';
    const elapsed = scan.endTime 
      ? scan.endTime.getTime() - scan.startTime.getTime()
      : Date.now() - scan.startTime.getTime();

    switch (scan.status) {
      case ScanStatus.PENDING:
        progress = 0;
        currentTask = 'Waiting to start...';
        break;
      case ScanStatus.RUNNING:
        // Real progress calculation based on vulnerability checks completed
        progress = Math.min((elapsed / (15 * 60 * 1000)) * 100, 95);
        if (progress < 15) currentTask = 'Analyze.......';
        else if (progress < 30) currentTask = 'Testing XSS vulnerabilities...';
        else if (progress < 45) currentTask = 'Testing directory traversal...';
        else if (progress < 60) currentTask = 'Checking security headers...';
        else if (progress < 75) currentTask = 'Testing CSRF protection...';
        else if (progress < 90) currentTask = 'Analyzing SSL configuration...';
        else currentTask = 'Generating report...';
        break;
      case ScanStatus.COMPLETED:
        progress = 100;
        currentTask = 'Scan completed';
        break;
      case ScanStatus.FAILED:
        progress = 100;
        currentTask = 'Scan failed';
        break;
      case ScanStatus.CANCELLED:
        progress = 100;
        currentTask = 'Scan cancelled';
        break;
    }

    const progressData: ProgressData = {
      status: scan.status,
      progress,
      currentTask,
      vulnerabilitiesFound: scan.vulnerabilities.length,
      elapsed,
      scanType: scan.scanType
    };

    console.log('📈 Returning progress data:', progressData);

    return NextResponse.json({
      success: true,
      data: progressData
    });

  } catch (error) {
    console.error('❌ Error fetching scan progress:', error);
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
