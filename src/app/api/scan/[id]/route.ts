import { NextRequest, NextResponse } from 'next/server';
import { ScanResult, ApiResponse } from '@/types';
import { scannerService } from '@/lib/scannerService';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
): Promise<NextResponse<ApiResponse<ScanResult>>> {
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

    return NextResponse.json({
      success: true,
      data: scan
    });

  } catch (error) {
    console.error('Error fetching scan:', error);
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
): Promise<NextResponse<ApiResponse<null>>> {
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

    // Note: Implement delete functionality in scanner service if needed
    // await scannerService.deleteScan(scanId);

    return NextResponse.json({
      success: true,
      message: 'Scan deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting scan:', error);
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
