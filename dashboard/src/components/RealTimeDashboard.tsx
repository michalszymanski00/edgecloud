'use client';

import React, { useState, useEffect, useMemo, useRef } from 'react';
import DashboardCard from './DashboardCard';
import TrendChart from './TrendChart';
import { Cpu, Wifi, WifiOff, Clock, AlertTriangle } from 'lucide-react';
import { fetchDevices, fetchCertExpiry } from '@/lib/api';

type Device = { id: string; last_seen: string };
type Expiry = { expired: number; expiring_soon: number };

export default function RealTimeDashboard() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [expiry, setExpiry] = useState<Expiry>({ expired: 0, expiring_soon: 0 });
  const wsRef = useRef<WebSocket | null>(null);  // WebSocket reference
  const reconnectIntervalRef = useRef<NodeJS.Timeout | null>(null);  // Reference for retry interval

  // 1) Initial load
  useEffect(() => {
    fetchDevices().then(setDevices).catch(console.error);
    fetchCertExpiry().then(setExpiry).catch(console.error);
  }, []);

  // 2) WebSocket subscription
  useEffect(() => {
    const url = process.env.NEXT_PUBLIC_WS_URL!;
    if (!url) {
      console.error('Missing NEXT_PUBLIC_WS_URL');
      return;
    }
  
    const createWebSocket = () => {
      const ws = new WebSocket(url);
  
      ws.onopen = () => {
        console.log('WS connected to', url);
        console.log('WS readyState on open:', ws.readyState); // Log readyState when the connection opens
      };
  
      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          if (msg.devices) setDevices(msg.devices);
          if (msg.expiry) setExpiry(msg.expiry);
        } catch (err) {
          console.error('WS payload parse error', err);
        }
      };
  
      ws.onerror = (ev) => {
        console.error('WebSocket error event:', ev);
        console.log('WS readyState after error:', ws.readyState); // Log readyState after the error occurs
  
        // Check if ev is an instance of ErrorEvent
        if (ev instanceof ErrorEvent) {
          console.error('Error message:', ev.message);
          console.error('Error filename:', ev.filename);
          console.error('Error lineno:', ev.lineno);
        } else {
          console.error('Error event does not contain a detailed error');
        }
  
        // Attempt reconnect if WebSocket fails
        console.log('Attempting to reconnect...');
        setTimeout(createWebSocket, 5000);  // Attempt to reconnect after 5 seconds
      };
  
      ws.onclose = (ev) => {
        console.log('WS closed with code:', ev.code, 'and reason:', ev.reason);
        console.log('WS readyState after close:', ws.readyState); // Log readyState after the connection closes
  
        // Attempt reconnect if WebSocket is closed
        console.log('Attempting to reconnect...');
        setTimeout(createWebSocket, 5000);  // Attempt to reconnect after 5 seconds
      };
  
      return ws;
    };
  
    const ws = createWebSocket();
  
    return () => {
      console.log('Closing WebSocket connection');
      ws.close();
    };
  }, []);  

  // 3) Derive metrics
  const total = devices.length;
  const online = devices.filter(
    (d) => Date.now() - new Date(d.last_seen).getTime() < 5 * 60 * 1000
  ).length;

  // 4) Build the 12×5‑minute buckets for the chart
  const intervals = useMemo(() => {
    const now = Date.now();
    return Array.from({ length: 12 }).map((_, i) => {
      const start = now - (11 - i) * 5 * 60 * 1000;
      const end = start + 5 * 60 * 1000;
      const count = devices.filter((d) => {
        const t = new Date(d.last_seen).getTime();
        return t >= start && t < end;
      }).length;
      return { timestamp: new Date(start).toISOString(), count };
    });
  }, [devices]);

  return (
    <>
      {/* Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-5 gap-4 mb-8">
        <DashboardCard
          title="Total Devices"
          value={total}
          icon={<Cpu />}
          iconBg="bg-gray-100"
          iconColor="text-gray-700"
        />
        <DashboardCard
          title="Online Devices"
          value={online}
          icon={<Wifi />}
          iconBg="bg-green-100"
          iconColor="text-green-500"
        />
        <DashboardCard
          title="Offline Devices"
          value={total - online}
          icon={<WifiOff />}
          iconBg="bg-red-100"
          iconColor="text-red-500"
        />
        <DashboardCard
          title="Expiring Soon"
          value={expiry.expiring_soon}
          icon={<Clock />}
          iconBg="bg-yellow-100"
          iconColor="text-yellow-600"
        />
        <DashboardCard
          title="Expired"
          value={expiry.expired}
          icon={<AlertTriangle />}
          iconBg="bg-red-100"
          iconColor="text-red-600"
        />
      </div>

      {/* Trend Chart */}
      <div className="mb-8">
        <TrendChart data={intervals} />
      </div>

      {/* Devices Table */}
      <div className="bg-white shadow rounded-lg overflow-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase">
                Device ID
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase">
                Last Seen
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {devices.map((d, idx) => (
              <tr key={`${d.id}-${idx}`}>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {d.id}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {new Date(d.last_seen).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
