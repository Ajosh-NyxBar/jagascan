import { NextRequest, NextResponse } from 'next/server';
import { ScanRequest, ScanResult, ScanStatus, ApiResponse } from '@/types';
import { scannerService } from '@/lib/scannerService';

export async function POST(request: NextRequest): Promise<NextResponse<ApiResponse<{ scanId: string }>>> {
  try {
    const body: ScanRequest = await request.json();
    
    // Validate request
    if (!body.target) {
      return NextResponse.json(
        { success: false, error: 'Target is required' },
        { status: 400 }
      );
    }

    if (!body.scanTypes || body.scanTypes.length === 0) {
      return NextResponse.json(
        { success: false, error: 'At least one scan type is required' },
        { status: 400 }
      );
    }

    // Start scan using scanner service
    const scanId = await scannerService.startScan(body);

    return NextResponse.json({
      success: true,
      data: { scanId },
      message: 'Scan started successfully'
    });

  } catch (error) {
    console.error('Error starting scan:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest): Promise<NextResponse<ApiResponse<ScanResult[]>>> {
  try {
    const { searchParams } = new URL(request.url);
    const status = searchParams.get('status') as ScanStatus;
    const limit = parseInt(searchParams.get('limit') || '10');
    const offset = parseInt(searchParams.get('offset') || '0');

    const filters = {
      ...(status && { status }),
      limit,
      offset
    };

    const scans = await scannerService.getAllScans(filters);

    return NextResponse.json({
      success: true,
      data: scans
    });

  } catch (error) {
    console.error('Error fetching scans:', error);
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
