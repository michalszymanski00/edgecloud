// src/app/workflows/[workflowId].tsx
'use client';

import { useRouter } from 'next/router';
import WorkflowForm from './create';

export default function EditWorkflow() {
  const router = useRouter();
  const { workflowId } = router.query;

  if (!workflowId) {
    return <div>Loading...</div>;
  }

  return <WorkflowForm workflowId={parseInt(workflowId as string)} />;
}
