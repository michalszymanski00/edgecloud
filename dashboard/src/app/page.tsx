"use client";

import { useEffect, useState } from 'react';
import api from '@/lib/api';

type Device = { id: string; last_seen: string };

export default function Home() {
  const [devices, setDevices] = useState<Device[]>([]);
  useEffect(() => {
    api.get<Device[]>('/devices').then(r => setDevices(r.data));
  }, []);

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold">Fleet Dashboard</h1>
      <table className="w-full mt-4 table-auto border">
        <thead>
          <tr>
            <th className="border px-2">Device ID</th>
            <th className="border px-2">Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {devices.map(d => (
            <tr key={d.id}>
              <td className="border px-2">{d.id}</td>
              <td className="border px-2">
                {new Date(d.last_seen).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
