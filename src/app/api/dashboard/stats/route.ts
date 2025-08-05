import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/database';
import { ApiResponse, DashboardStats } from '@/types';

export async function GET(request: NextRequest): Promise<NextResponse<ApiResponse<DashboardStats>>> {
  try {
    const db = getDatabase();
    const stats = await db.getDashboardStats();

    return NextResponse.json({
      success: true,
      data: stats
    });

  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
