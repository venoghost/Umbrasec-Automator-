import axios from 'axios';
import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { ip } = body;

    if (!ip || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
      return NextResponse.json(
        { error: 'Valid IP address required' },
        { status: 400 }
      );
    }

    const response = await axios.get(`https://internetdb.shodan.io/${ip}`, {
      signal: AbortSignal.timeout(10000) // 10s timeout
    });

    return NextResponse.json(response.data);

  } catch (error) {
    console.error('Scan error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Failed to fetch data from InternetDB';
    
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}