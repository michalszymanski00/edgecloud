// src/app/page.tsx
'use client';

import React from 'react';
import RealTimeDashboard from '@/components/RealTimeDashboard';

export default function DashboardPage() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-semibold text-gray-900 mb-6">
        Fleet Dashboard
      </h1>
      <RealTimeDashboard />
    </div>
  );
}
