'use client';

import React from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';

interface TrendChartProps {
  data: { timestamp: string; count: number }[];
}

export default function TrendChart({ data }: TrendChartProps) {
  return (
    <div className="bg-white shadow rounded-lg p-5">
      <h2 className="text-lg font-medium text-gray-900 mb-4">Conn. Trends (1h)</h2>
      <ResponsiveContainer width="100%" height={150}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis
            dataKey="timestamp"
            tickFormatter={(ts) => new Date(ts).toLocaleTimeString([], { hour: 'numeric', minute: 'numeric' })}
            axisLine={false}
            tickLine={false}
            interval="preserveStartEnd"
          />
          <YAxis
            allowDecimals={false}
            axisLine={false}
            tickLine={false}
            width={20}
          />
          <Tooltip
            labelFormatter={(ts) => new Date(ts).toLocaleString()}
            formatter={(val: number) => [`${val}`, 'Devices']}
          />
          <Line
            type="monotone"
            dataKey="count"
            stroke="#3b82f6"
            dot={false}
            strokeWidth={2}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
