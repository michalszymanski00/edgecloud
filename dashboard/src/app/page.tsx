// src/app/page.tsx
import axios, { fetchDevices } from '@/lib/api';
import DashboardCard from '../components/DashboardCard';
import TrendChart     from '../components/TrendChart';
import { Cpu, Wifi, WifiOff } from 'lucide-react';

export default async function DashboardPage() {
  // fetch devices on the server
  const devices = await fetchDevices(); // returns { id, last_seen }[]

  // metrics
  const total = devices.length;
  const online = devices.filter(d =>
    Date.now() - new Date(d.last_seen).getTime() < 5 * 60 * 1000
  ).length;

  // build 5-minute buckets over the last hour
  const now = Date.now();
  const intervals = Array.from({ length: 12 }).map((_, i) => {
    const start = now - (11 - i) * 5 * 60 * 1000;
    const end   = start + 5 * 60 * 1000;
    const count = devices.filter(d => {
      const t = new Date(d.last_seen).getTime();
      return t >= start && t < end;
    }).length;
    return { timestamp: new Date(start).toISOString(), count };
  });

  return (
    <>
      <h1 className="text-2xl font-semibold text-gray-900 mb-6">
        Fleet Dashboard
      </h1>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
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
