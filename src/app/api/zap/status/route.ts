import { NextRequest, NextResponse } from 'next/server';
import { ZAPIntegrationService } from '@/lib/zapIntegration';
import { ApiResponse } from '@/types/index';

export async function GET(request: NextRequest): Promise<NextResponse<ApiResponse<any>>> {
  try {
    const { searchParams } = new URL(request.url);
    const zapUrl = searchParams.get('zapUrl') || 'http://localhost:8080';
    const apiKey = searchParams.get('apiKey') || '4ke0djgc9n5v2mqv9582via78e';

    console.log('🔗 Testing ZAP connection to:', zapUrl);

    const zapService = new ZAPIntegrationService({
      zapUrl,
      apiKey,
      timeout: 10000
    });

    const result = await zapService.testConnection();

    if (result.connected) {
      console.log('✅ ZAP connection successful, version:', result.version);
      return NextResponse.json({
        success: true,
        data: {
          connected: true,
          version: result.version,
          message: 'Successfully connected to OWASP ZAP'
        }
      });
    } else {
      console.log('❌ ZAP connection failed:', result.error);
      return NextResponse.json({
        success: false,
        error: result.error || 'Failed to connect to ZAP',
        data: {
          connected: false
        }
      }, { status: 503 });
    }

  } catch (error) {
    console.error('❌ ZAP status check error:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Internal server error',
      data: {
        connected: false
      }
    }, { status: 500 });
  }
}
