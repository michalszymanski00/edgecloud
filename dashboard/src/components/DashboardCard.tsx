// src/components/DashboardCard.tsx
'use client';

import React from 'react';

interface DashboardCardProps {
  title: string;
  value: number | string;
  /** We expect an SVG-based icon that accepts className and size props */
  icon: React.ReactElement<{
    className?: string;
    size?: number;
  }>;
  /** background of the icon wrapper, e.g. "bg-green-100" */
  iconBg?: string;
  /** color of the icon, e.g. "text-green-500" */
  iconColor?: string;
}

export default function DashboardCard({
  title,
  value,
  icon,
  iconBg = 'bg-blue-100',
  iconColor = 'text-blue-500',
}: DashboardCardProps) {
  return (
    <div className="bg-white shadow rounded-lg p-5 flex items-center">
      <div className={`p-3 rounded-full mr-4 ${iconBg}`}>
        {React.cloneElement(icon, {
          className: iconColor,
          size: 24,
        })}
      </div>
      <div>
        <p className="text-sm text-gray-500">{title}</p>
        <p className="text-2xl font-semibold text-gray-900">{value}</p>
      </div>
    </div>
  );
}