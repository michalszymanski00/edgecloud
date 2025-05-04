// src/lib/api.ts
import axios from 'axios';
import https from 'https';

const devAgent = new https.Agent({
  // only reject invalid certs in production
  rejectUnauthorized: process.env.NODE_ENV === 'production',
});

/**
 * Core HTTP client.
 * Tries ENROLL first, then control‑plane admin, then public API base.
 */
const client = axios.create({
  baseURL:
    process.env.NEXT_PUBLIC_ENROLL_URL ||
    process.env.API_BASE_URL ||
    process.env.NEXT_PUBLIC_API_URL,
  httpsAgent: devAgent,
});

export type WorkflowIn = {
  name: string;
  definition: object;
  schedule?: string;
  recurrence?: string;
};

export default client;

/** Fetch the list of devices (public). */
export function fetchDevices(): Promise<{ id: string; last_seen: string }[]> {
  return client.get('/devices').then((r) => r.data);
}

/** Fetch workflows for a single device. */
export function fetchWorkflows(deviceId: string): Promise<{ id: number; name: string; status: string; schedule: string | null }[]> {
  return client.get(`/devices/${deviceId}/workflows`).then((r) => r.data);
}

/** Fetch logs for a single device. */
export function fetchLogs(deviceId: string): Promise<{ timestamp: string; message: string }[]> {
  return client.get(`/devices/${deviceId}/logs`).then((r) => r.data);
}

/** Fetch workflow details by device and workflow ID. */
export function fetchWorkflowDetails(deviceId: string, workflowId: number): Promise<{ id: number; name: string; status: string; definition: object; schedule: string | null }> {
  return client
    .get(`/devices/${deviceId}/workflows/${workflowId}`)
    .then((r) => r.data);
}

// ——— Admin endpoints ———
const adminHeaders = {
  'X-Admin-Token': process.env.NEXT_PUBLIC_REG_TOKEN!,
};

/** List all device tokens. */
export function fetchTokens(): Promise<{ device_id: string; token: string }[]> {
  return client.get('/tokens', { headers: adminHeaders }).then((r) => r.data);
}

/** Create a new device token. */
export function createToken(): Promise<{ device_id: string; token: string }> {
  return client.post('/tokens', {}, { headers: adminHeaders }).then((r) => r.data);
}

/** Revoke a device token. */
export function deleteToken(deviceId: string): Promise<void> {
  return client
    .delete(`/tokens/${deviceId}`, { headers: adminHeaders })
    .then(() => {});
}

// ——— Enrollment (CSR → signed cert) ———

/**
 * Register a device by submitting its CSR.
 * Proxied through our Next.js API at /api/register
 * so that we can inject the X‑Register‑Token server‑side.
 */
export function registerDevice(deviceId: string, csrPem: string): Promise<{ cert: string; ca: string }> {
  return axios
    .post<{ cert: string; ca: string }>('/api/register', { device_id: deviceId, csr_pem: csrPem })
    .then((r) => r.data);
}

// ——— Certificate‐expiry endpoints ———

/**
 * Fetch a list of certs that will expire within 30 days.
 * Returns an array of { device_id, not_after }.
 */
export function fetchExpiringCerts(): Promise<{ device_id: string; not_after: string }[]> {
  return client.get('/admin/certs/expiring', { headers: adminHeaders }).then((r) => r.data);
}

/**
 * Fetch a list of already‐expired certificates.
 * (Assumes your control‐plane offers /admin/certs/expired.)
 */
export function fetchExpiredCerts(): Promise<{ device_id: string; not_after: string }[]> {
  return client.get('/admin/certs/expired', { headers: adminHeaders }).then((r) => r.data);
}

/**
 * Return a simple summary { expired, expiring_soon }
 * by calling the two endpoints above.
 */
export async function fetchCertExpiry(): Promise<{ expired: number; expiring_soon: number }> {
  const [expiring, expired] = await Promise.all([fetchExpiringCerts(), fetchExpiredCerts()]);
  return {
    expiring_soon: expiring.length,
    expired: expired.length,
  };
}

// src/lib/api.ts
export function createWorkflow(deviceId: string, workflow: WorkflowIn) {
  return client.post(`/devices/${deviceId}/workflows`, workflow);
}

export function updateWorkflow(deviceId: string, workflowId: number, workflow: WorkflowIn) {
  return client.put(`/devices/${deviceId}/workflows/${workflowId}`, workflow);
}

export function deleteWorkflow(deviceId: string, workflowId: number) {
  return client.delete(`/devices/${deviceId}/workflows/${workflowId}`);
}
