import { NextRequest, NextResponse } from 'next/server';
import { ZAPIntegrationService } from '@/lib/zapIntegration';
import { scannerService } from '@/lib/scannerService';
import { ApiResponse, ScanStatus } from '@/types';

interface ZAPProgressData {
  status: ScanStatus;
  progress: number;
  currentTask: string;
  vulnerabilitiesFound: number;
  elapsed: number;
  scanType: string;
  phase?: string;
  spiderProgress?: number;
  activeScanProgress?: number;
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
): Promise<NextResponse<ApiResponse<ZAPProgressData>>> {
  try {
    const { id: scanId } = await params;
    console.log('🔍 ZAP Progress API called for scanId:', scanId);
    
    if (!scanId) {
      console.log('❌ No scan ID provided');
      return NextResponse.json(
        { success: false, error: 'Scan ID is required' },
        { status: 400 }
      );
    }

    // First, try to get scan from database
    console.log('📊 Looking up ZAP scan in database...');
    const scan = await scannerService.getScanResult(scanId);
    
    if (!scan) {
      console.log('❌ ZAP scan not found in database for ID:', scanId);
      return NextResponse.json(
        { success: false, error: 'ZAP scan not found' },
        { status: 404 }
      );
    }

    console.log('✅ ZAP scan found:', {
      id: scan.id,
      status: scan.status,
      vulnerabilities: scan.vulnerabilities.length,
      startTime: scan.startTime,
      zapConfig: scan.metadata?.zapConfig
    });

    // Get ZAP-specific progress from ZAP service if scan is still running
    let zapProgress = null;
    if (scan.status === ScanStatus.RUNNING && scan.metadata?.zapConfig) {
      try {
        console.log('🔄 Getting live progress from ZAP...');
        const zapService = new ZAPIntegrationService({
          zapUrl: scan.metadata.zapConfig.zapUrl || 'http://localhost:8080',
          apiKey: scan.metadata.zapConfig.apiKey || '4ke0djgc9n5v2mqv9582via78e',
          timeout: 10000
        });

        zapProgress = await zapService.getScanProgress(
          scanId,
          scan.metadata.zapConfig.spiderScanId,
          scan.metadata.zapConfig.activeScanId
        );
        console.log('📊 Live ZAP progress:', zapProgress);
      } catch (error) {
        console.error('⚠️ Could not get live ZAP progress:', error);
      }
    }

    // Calculate progress based on scan status and elapsed time
    let progress = 0;
    let currentTask = 'Initializing ZAP scan...';
    const elapsed = scan.endTime 
      ? scan.endTime.getTime() - scan.startTime.getTime()
      : Date.now() - scan.startTime.getTime();

    switch (scan.status) {
      case ScanStatus.PENDING:
        progress = 0;
        currentTask = 'Waiting to start ZAP scan...';
        break;
      case ScanStatus.RUNNING:
        if (zapProgress) {
          progress = zapProgress.overallProgress;
          currentTask = zapProgress.currentTask;
        } else {
          // Fallback progress calculation
          progress = Math.min((elapsed / (20 * 60 * 1000)) * 100, 95);
          if (progress < 20) currentTask = 'Spider crawling website...';
          else if (progress < 40) currentTask = 'Passive security analysis...';
          else if (progress < 60) currentTask = 'Active vulnerability testing...';
          else if (progress < 80) currentTask = 'SQL injection testing...';
          else if (progress < 90) currentTask = 'XSS vulnerability testing...';
          else currentTask = 'Finalizing security report...';
        }
        break;
      case ScanStatus.COMPLETED:
        progress = 100;
        currentTask = 'ZAP scan completed';
        break;
      case ScanStatus.FAILED:
        progress = 100;
        currentTask = 'ZAP scan failed';
        break;
      case ScanStatus.CANCELLED:
        progress = 100;
        currentTask = 'ZAP scan cancelled';
        break;
    }

    const progressData: ZAPProgressData = {
      status: scan.status,
      progress,
      currentTask,
      vulnerabilitiesFound: scan.vulnerabilities.length,
      elapsed,
      scanType: scan.scanType,
      ...(zapProgress && {
        phase: zapProgress.phase,
        spiderProgress: zapProgress.spiderProgress,
        activeScanProgress: zapProgress.activeScanProgress
      })
    };

    console.log('📈 Returning ZAP progress data:', progressData);

    return NextResponse.json({
      success: true,
      data: progressData
    });

  } catch (error) {
    console.error('❌ Error fetching ZAP scan progress:', error);
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
