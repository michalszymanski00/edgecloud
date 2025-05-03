// dashboard/src/app/devices/page.tsx
"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { fetchDevices } from "@/lib/api";

export default function DevicesPage() {
  const [devices, setDevices] = useState<{ id: string; last_seen: string }[]>([]);

  useEffect(() => {
    fetchDevices().then(setDevices).catch(console.error);
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Devices</h1>
      <ul className="space-y-2">
        {devices.map((d) => (
          <li key={d.id} className="p-2 border rounded hover:bg-gray-50">
            <Link href={`/devices/${d.id}`}>
              <a className="text-blue-600 hover:underline">
                {d.id} &mdash; last seen {new Date(d.last_seen).toLocaleString()}
              </a>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
