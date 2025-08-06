import { NextRequest, NextResponse } from 'next/server';
import { ZAPIntegrationService, ZAPScanOptions } from '@/lib/zapIntegration';
import { scannerService } from '@/lib/scannerService';
import { ApiResponse, ScanType, ScanOptions, ScanStatus } from '@/types/index';

interface ZAPScanRequest {
  target: string;
  scanTypes: ScanType[];
  options?: ScanOptions;
  zapConfig?: {
    zapUrl?: string;
    apiKey?: string;
    spiderMaxDepth?: number;
    spiderMaxChildren?: number;
    enableActiveScan?: boolean;
    enablePassiveScan?: boolean;
  };
}

export async function POST(request: NextRequest): Promise<NextResponse<ApiResponse<any>>> {
  try {
    const body: ZAPScanRequest = await request.json();
    const { target, zapConfig } = body;

    if (!target) {
      return NextResponse.json({
        success: false,
        error: 'Target URL is required'
      }, { status: 400 });
    }

    console.log('🚀 Starting ZAP-enhanced scan for:', target);

    // Configure ZAP integration
    const zapService = new ZAPIntegrationService({
      zapUrl: zapConfig?.zapUrl || 'http://localhost:8080',
      apiKey: zapConfig?.apiKey || '4ke0djgc9n5v2mqv9582via78e',
      timeout: 30000
    });

    // Test connection first
    const connectionTest = await zapService.testConnection();
    if (!connectionTest.connected) {
      return NextResponse.json({
        success: false,
        error: `ZAP connection failed: ${connectionTest.error}`
      }, { status: 503 });
    }

    // Configure ZAP scan options
    const zapScanOptions: ZAPScanOptions = {
      spiderMaxDepth: zapConfig?.spiderMaxDepth || 5,
      spiderMaxChildren: zapConfig?.spiderMaxChildren || 10,
      enableActiveScan: zapConfig?.enableActiveScan !== false,
      enablePassiveScan: zapConfig?.enablePassiveScan !== false,
      contextName: 'JagaScan'
    };

    // Start ZAP scan
    const scanResult = await zapService.startScan(target, zapScanOptions);

    if (!scanResult.success) {
      return NextResponse.json({
        success: false,
        error: scanResult.error || 'Failed to start ZAP scan'
      }, { status: 500 });
    }

    console.log('✅ ZAP scan started successfully:', scanResult.scanId);

    // Save ZAP scan to database
    try {
      await scannerService.createZAPScanRecord({
        scanId: scanResult.scanId,
        target,
        scanTypes: body.scanTypes || [ScanType.WEB_VULNERABILITY],
        zapConfig: {
          zapUrl: zapConfig?.zapUrl || 'http://localhost:8080',
          apiKey: zapConfig?.apiKey || '4ke0djgc9n5v2mqv9582via78e',
          spiderScanId: scanResult.spiderScanId,
          activeScanId: scanResult.activeScanId
        }
      });
      console.log('💾 ZAP scan saved to database:', scanResult.scanId);
    } catch (dbError) {
      console.error('⚠️ Failed to save ZAP scan to database:', dbError);
      // Don't fail the scan, just log the error
    }

    return NextResponse.json({
      success: true,
      data: {
        scanId: scanResult.scanId,
        spiderScanId: scanResult.spiderScanId,
        activeScanId: scanResult.activeScanId,
        target,
        zapVersion: connectionTest.version,
        message: 'ZAP-enhanced security scan started successfully'
      }
    });

  } catch (error) {
    console.error('❌ ZAP scan error:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Internal server error'
    }, { status: 500 });
  }
}

export async function GET(request: NextRequest): Promise<NextResponse<ApiResponse<any>>> {
  try {
    const { searchParams } = new URL(request.url);
    const scanId = searchParams.get('scanId');
    const spiderScanId = searchParams.get('spiderScanId');
    const activeScanId = searchParams.get('activeScanId');
    const zapUrl = searchParams.get('zapUrl') || 'http://localhost:8080';
    const apiKey = searchParams.get('apiKey') || '4ke0djgc9n5v2mqv9582via78e';

    if (!scanId) {
      return NextResponse.json({
        success: false,
        error: 'Scan ID is required'
      }, { status: 400 });
    }

    console.log('📊 Getting ZAP scan progress for:', scanId);

    const zapService = new ZAPIntegrationService({
      zapUrl,
      apiKey,
      timeout: 10000
    });

    const progress = await zapService.getScanProgress(
      scanId, 
      spiderScanId || undefined, 
      activeScanId || undefined
    );

    return NextResponse.json({
      success: true,
      data: {
        scanId,
        phase: progress.phase,
        progress: progress.overallProgress,
        spiderProgress: progress.spiderProgress,
        activeScanProgress: progress.activeScanProgress,
        currentTask: progress.currentTask,
        vulnerabilitiesFound: progress.alertsFound,
        status: progress.phase === 'completed' ? 'completed' : 
                progress.phase === 'failed' ? 'failed' : 'running'
      }
    });

  } catch (error) {
    console.error('❌ Error getting ZAP scan progress:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to get scan progress'
    }, { status: 500 });
  }
}
