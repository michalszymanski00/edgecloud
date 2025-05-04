// src/lib/api.ts
import axios from 'axios';
import https from 'https';

const devAgent = new https.Agent({
  rejectUnauthorized: process.env.NODE_ENV === 'production',
});

const client = axios.create({
  baseURL:
    process.env.NEXT_PUBLIC_ENROLL_URL ||
    process.env.API_BASE_URL ||
    process.env.NEXT_PUBLIC_API_URL,
  httpsAgent: devAgent,
});

export default client;

/** Fetch the list of devices. (no auth header) */
export function fetchDevices() {
  return client
    .get<{ id: string; last_seen: string }[]>('/devices')
    .then(res => res.data);
}

/** Fetch workflows for a device. */
export function fetchWorkflows(deviceId: string) {
  return client
    .get<{ id: number; name: string; status: string }[]>(
      `/devices/${deviceId}/workflows`
    )
    .then(res => res.data);
}

/** Fetch logs for a device. */
export function fetchLogs(deviceId: string) {
  return client
    .get<{ timestamp: string; message: string }[]>(
      `/devices/${deviceId}/logs`
    )
    .then(res => res.data);
}

/** List all device tokens (admin endpoint). */
export function fetchTokens() {
  return client
    .get<{ device_id: string; token: string }[]>('/tokens', {
      headers: { 'X-Admin-Token': process.env.NEXT_PUBLIC_REG_TOKEN! },
    })
    .then(res => res.data);
}

/** Create a new device token (admin endpoint). */
export function createToken() {
  return client
    .post<{ device_id: string; token: string }>(
      '/tokens',
      {},
      { headers: { 'X-Admin-Token': process.env.NEXT_PUBLIC_REG_TOKEN! } }
    )
    .then(res => res.data);
}

/** Revoke a device token (admin endpoint). */
export function deleteToken(token: string) {
  return client.delete(`/tokens/${token}`, {
      headers: { 'X-Admin-Token': process.env.NEXT_PUBLIC_REG_TOKEN! },
    })
    .then(() => {});
}

export function registerDevice(deviceId: string, csrPem: string) {
  return axios
    .post<{ cert: string; ca: string }>('/api/register', { device_id: deviceId, csr_pem: csrPem })
    .then(res => res.data);
}
