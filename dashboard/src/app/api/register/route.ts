// src/app/api/register/route.ts

import { NextResponse } from 'next/server';
import https from 'https';
import axios from 'axios';

// Only skip TLS validation in dev
const agent = new https.Agent({
  rejectUnauthorized: process.env.NODE_ENV === 'production',
});

const client = axios.create({
  baseURL: process.env.ENROLL_API_URL, // e.g. https://192.168.0.94:8444
  httpsAgent: agent,
});

export async function POST(req: Request) {
  console.log('Server sees NEXT_PUBLIC_REG_TOKEN =', process.env.NEXT_PUBLIC_REG_TOKEN);
  const { device_id, csr_pem } = await req.json();
  if (!device_id || !csr_pem) {
    return NextResponse.json(
      { error: 'device_id and csr_pem required' },
      { status: 400 }
    );
  }

  try {
    const apiRes = await client.post(
      '/register',
      { device_id, csr_pem },
      {
        headers: {
          'X-Register-Token': process.env.NEXT_PUBLIC_REG_TOKEN!,  // use the same token your API seeded
          'Content-Type': 'application/json',
        },
      }
    );
    return NextResponse.json(apiRes.data);
  } catch (err: any) {
    const status = err.response?.status || 500;
    const data = err.response?.data || { error: 'Unknown error' };
    console.error('Proxy /api/register error:', status, data);
    return NextResponse.json(data, { status });
  }
}
