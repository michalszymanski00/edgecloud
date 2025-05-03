// dashboard/src/app/devices/[id]/page.tsx
"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { fetchWorkflows, fetchLogs } from "@/lib/api";

type Workflow = {
  id: number;
  name: string;
  schedule?: string;
  recurrence?: string;
};

type Log = {
  id: number;
  ts: string;
  success: boolean;
  output?: string;
};

export default function DeviceDetailsPage() {
  const router = useRouter();
  const { id } = router.query as { id: string };

  const [workflows, setWorkflows] = useState<Workflow[]>([]);
  const [logs, setLogs] = useState<Record<number, Log[]>>({});

  useEffect(() => {
    if (!id) return;
    fetchWorkflows(id).then(setWorkflows).catch(console.error);
  }, [id]);

  useEffect(() => {
    if (!id) return;
    workflows.forEach((wf) => {
      fetchLogs(id, wf.id).then((l) =>
        setLogs((old) => ({ ...old, [wf.id]: l }))
      ).catch(console.error);
    });
  }, [id, workflows]);

  return (
    <div className="p-4 space-y-6">
      <h1 className="text-2xl font-bold">Device: {id}</h1>

      <section>
        <h2 className="text-xl font-semibold mb-2">Workflows</h2>
        {workflows.map((wf) => (
          <div key={wf.id} className="mb-4 p-3 border rounded">
            <div className="font-medium">{wf.name}</div>
            <div className="text-sm text-gray-600">
              {wf.schedule ?? wf.recurrence ?? "— no schedule —"}
            </div>
            <ul className="mt-2 text-sm">
              {(logs[wf.id] || []).map((log) => (
                <li key={log.id} className="mb-1">
                  <span
                    className={log.success ? "text-green-600" : "text-red-600"}
                  >
                    {log.success ? "✔" : "✖"}
                  </span>{" "}
                  {new Date(log.ts).toLocaleTimeString()}: {log.output}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </section>
    </div>
  );
}
