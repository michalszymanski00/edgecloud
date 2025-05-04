// src/app/workflows/create.tsx
'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import { fetchDevices, createWorkflow, WorkflowIn } from '@/lib/api'; // Correct import
import { useParams } from 'next/navigation';

export default function WorkflowForm({ workflowId }: { workflowId?: number }) {
  const [devices, setDevices] = useState<{ id: string }[]>([]);
  const [workflow, setWorkflow] = useState<WorkflowIn>({
    name: '',
    definition: {},
    schedule: '',
    recurrence: '',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const router = useRouter();

  useEffect(() => {
    fetchDevices().then(deviceList => setDevices(deviceList)).catch(console.error);

    if (workflowId) {
      // Fetch workflow details if editing an existing workflow
      // This should be an API call fetching the specific workflow
      // For now, mock the data
      setWorkflow({
        name: 'Example Workflow',
        definition: {},
        schedule: '0 0 * * *',
        recurrence: 'daily',
      });
    }
  }, [workflowId]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    // Use the appropriate API call here (either create or update)
    // Mock the API request as an example:
    try {
      if (workflowId) {
        // Assuming update workflow if workflowId exists
        // await updateWorkflow(workflow);
        console.log('Updating Workflow:', workflow);
      } else {
        await createWorkflow('deviceId', workflow); // Replace with actual device ID
        console.log('Creating Workflow:', workflow);
      }
      router.push('/workflows');
    } catch (error) {
      console.error('Error submitting workflow', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-semibold">{workflowId ? 'Edit' : 'Create'} Workflow</h1>
      <form onSubmit={handleSubmit} className="mt-6">
        <label className="block">
          <span className="text-gray-700">Name</span>
          <input
            type="text"
            value={workflow.name}
            onChange={(e) => setWorkflow({ ...workflow, name: e.target.value })}
            className="mt-1 p-2 w-full border rounded-md"
          />
        </label>

        <label className="block mt-4">
          <span className="text-gray-700">Schedule (Cron format)</span>
          <input
            type="text"
            value={workflow.schedule}
            onChange={(e) => setWorkflow({ ...workflow, schedule: e.target.value })}
            className="mt-1 p-2 w-full border rounded-md"
          />
        </label>

        <label className="block mt-4">
          <span className="text-gray-700">Recurrence</span>
          <input
            type="text"
            value={workflow.recurrence}
            onChange={(e) => setWorkflow({ ...workflow, recurrence: e.target.value })}
            className="mt-1 p-2 w-full border rounded-md"
          />
        </label>

        <button
          type="submit"
          disabled={isSubmitting}
          className="mt-4 p-2 bg-blue-500 text-white rounded-md"
        >
          {isSubmitting ? 'Submitting...' : 'Submit'}
        </button>
      </form>
    </div>
  );
}
