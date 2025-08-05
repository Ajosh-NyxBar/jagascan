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
    
    if (!scanId) {
      return NextResponse.json(
        { success: false, error: 'Scan ID is required' },
        { status: 400 }
      );
    }

    const scan = await scannerService.getScanResult(scanId);
    
    if (!scan) {
      return NextResponse.json(
        { success: false, error: 'Scan not found' },
        { status: 404 }
      );
    }

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
        // Simulate progress based on elapsed time (max 15 minutes)
        progress = Math.min((elapsed / (15 * 60 * 1000)) * 100, 95);
        if (progress < 20) currentTask = 'Initializing scan...';
        else if (progress < 40) currentTask = 'Crawling target...';
        else if (progress < 60) currentTask = 'Testing for vulnerabilities...';
        else if (progress < 80) currentTask = 'Analyzing results...';
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

    return NextResponse.json({
      success: true,
      data: progressData
    });

  } catch (error) {
    console.error('Error fetching scan progress:', error);
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
