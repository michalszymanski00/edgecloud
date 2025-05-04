// src/app/workflows/page.tsx

'use client';

import { useEffect, useState } from 'react';
import { fetchDevices, fetchWorkflows } from '@/lib/api'; // Reusing the fetchDevices from the API file
import Link from 'next/link';

type Workflow = {
  id: number;
  name: string;
  schedule: string;
  created_at: string | null;  // Allow null values
  updated_at: string | null;  // Allow null values
};

export default function WorkflowsPage() {
  const [devices, setDevices] = useState<{ id: string }[]>([]);
  const [workflows, setWorkflows] = useState<Workflow[]>([]);

  // Fetch devices on load
  useEffect(() => {
    fetchDevices().then((deviceList) => {
      setDevices(deviceList);
    }).catch(console.error);
  }, []);

  // Fetch workflows for a device
  const handleDeviceClick = async (deviceId: string) => {
    const fetchedWorkflows = await fetchWorkflows(deviceId);
    const formattedWorkflows = fetchedWorkflows.map((workflow: any) => ({
      ...workflow,
      created_at: workflow.created_at || null,  // Ensure created_at is set to null if missing
      updated_at: workflow.updated_at || null,  // Ensure updated_at is set to null if missing
    }));
    setWorkflows(formattedWorkflows);
  };

  return (
    <div>
      <h1 className="text-2xl font-semibold">Manage Workflows</h1>

      <div className="mt-6">
        <h2 className="text-xl">Devices</h2>
        <div className="grid grid-cols-3 gap-4">
          {devices.map(device => (
            <button
              key={device.id}
              onClick={() => handleDeviceClick(device.id)}
              className="bg-blue-500 text-white p-4 rounded-lg"
            >
              {device.id}
            </button>
          ))}
        </div>
      </div>

      <div className="mt-6">
        <h2 className="text-xl">Workflows</h2>
        {workflows.length > 0 ? (
          <ul className="space-y-4">
            {workflows.map(workflow => (
              <li key={workflow.id} className="bg-gray-200 p-4 rounded-lg">
                <h3 className="text-lg">{workflow.name}</h3>
                <p>Schedule: {workflow.schedule}</p>
                <p>Created: {workflow.created_at}</p>
                <p>Updated: {workflow.updated_at}</p>
                <div className="mt-2">
                  <Link href={`/workflows/${workflow.id}`} className="text-blue-500">
                    Edit Workflow
                  </Link>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p>No workflows found for this device.</p>
        )}
      </div>
    </div>
  );
}
