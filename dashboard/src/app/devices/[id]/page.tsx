'use client';

import { useParams } from 'next/navigation';
import { useEffect, useState } from 'react';
import { fetchWorkflows, fetchLogs } from '@/lib/api';

type Workflow = { id: number; name: string; status: string };
type LogEntry  = { timestamp: string; message: string };

export default function DeviceDetailPage() {
  const params = useParams();
  const idParam = params.id;  // string | string[] | undefined

  const [workflows, setWorkflows] = useState<Workflow[]>([]);
  const [logs, setLogs]           = useState<LogEntry[]>([]);

  useEffect(() => {
    // Only proceed if idParam is a single string
    if (!idParam || Array.isArray(idParam)) return;

    const deviceId = idParam;
    fetchWorkflows(deviceId)
      .then(setWorkflows)
      .catch(console.error);

    fetchLogs(deviceId)
      .then(setLogs)
      .catch(console.error);
  }, [idParam]);

  // If for some reason idParam is missing or invalid, render nothing or a message
  if (!idParam || Array.isArray(idParam)) {
    return <p className="p-6 text-red-500">Invalid device ID</p>;
  }

  return (
    <div className="p-6">
      <h1 className="text-2xl font-semibold mb-4">Device: {idParam}</h1>

      <section className="mb-6">
        <h2 className="text-xl font-medium mb-2">Workflows</h2>
        <ul className="list-disc list-inside">
          {workflows.map(w => (
            <li key={w.id}>
              {w.name} — <span className="font-semibold">{w.status}</span>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2 className="text-xl font-medium mb-2">Logs</h2>
        <div className="space-y-2 max-h-64 overflow-auto">
          {logs.map((l, i) => (
            <div key={i} className="text-sm text-gray-700">
              <time className="font-mono">{new Date(l.timestamp).toLocaleString()}</time>
              : {l.message}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
