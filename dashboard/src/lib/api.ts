import axios from 'axios';

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL,
});

export async function listDevices() {
  const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/devices`)
  return res.json()
}

export async function listWorkflows(deviceId: string) {
  const res = await fetch(
    `${process.env.NEXT_PUBLIC_API_URL}/devices/${deviceId}/workflows`,
    { headers: { "X-Register-Token": process.env.NEXT_PUBLIC_REG_TOKEN! } }
  )
  return res.json()
}

export async function listLogs(deviceId: string, wfId: number) {
  const res = await fetch(
    `${process.env.NEXT_PUBLIC_API_URL}/devices/${deviceId}/workflows/${wfId}/logs`,
    { headers: { "X-Register-Token": process.env.NEXT_PUBLIC_REG_TOKEN! } }
  )
  return res.json()
}

export default api;
