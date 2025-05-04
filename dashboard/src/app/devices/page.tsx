'use client';

import { useEffect, useState } from "react";
import Link from "next/link";
import { fetchDevices } from "@/lib/api";

export default function DevicesPage() {
  const [devices, setDevices] = useState<{ id: string; last_seen: string }[]>([]);

  useEffect(() => {
    fetchDevices().then(setDevices).catch(console.error);
  }, []);

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4 text-gray-900">Devices</h1>

      {/* Card container */}
      <div className="bg-white shadow rounded-lg overflow-hidden">
        <ul>
          {devices.map((d) => (
            <li
              key={d.id}
              className="px-4 py-3 border-b last:border-b-0 bg-gray-50 hover:bg-gray-100 transition-colors"
            >
              <Link href={`/devices/${d.id}`}>
                <span className="text-gray-800 hover:text-blue-600">
                  {d.id} &mdash; last seen {new Date(d.last_seen).toLocaleString()}
                </span>
              </Link>
            </li>
          ))}
          {devices.length === 0 && (
            <li className="px-4 py-3 text-gray-500">No devices found.</li>
          )}
        </ul>
      </div>
    </div>
  );
}
