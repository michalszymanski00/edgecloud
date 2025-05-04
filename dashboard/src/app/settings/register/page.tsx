// src/app/settings/register/page.tsx
'use client';

import React, { useState } from 'react';
import { registerDevice } from '@/lib/api';

export default function RegisterPage() {
  const [deviceId, setDeviceId] = useState('');
  const [csrText, setCsrText]   = useState('');
  const [certPem, setCertPem]   = useState('');
  const [caPem, setCaPem]       = useState('');
  const [loading, setLoading]   = useState(false);

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setCsrText(reader.result as string);
    reader.readAsText(file);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!deviceId.trim()) {
      alert('Please enter a Device ID.');
      return;
    }
    if (!csrText) {
      alert('Please paste or upload a CSR first.');
      return;
    }

    setLoading(true);
    try {
      const { cert, ca } = await registerDevice(deviceId.trim(), csrText);
      setCertPem(cert);
      setCaPem(ca);
    } catch (err: any) {
      console.error('Enrollment failed:', err.response?.status, err.response?.data);
      alert(`Enrollment failed (status ${err.response?.status}):\n${JSON.stringify(err.response?.data)}`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 max-w-2xl mx-auto">
      <h1 className="text-2xl font-semibold mb-6 text-gray-900">
        Register Device
      </h1>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Device ID */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Device ID
          </label>
          <input
            type="text"
            value={deviceId}
            onChange={e => setDeviceId(e.target.value)}
            placeholder="e.g. pi-01"
            className="w-full px-3 py-2 border rounded focus:outline-none focus:ring"
          />
        </div>

        {/* Paste CSR */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Paste CSR
          </label>
          <textarea
            value={csrText}
            onChange={e => setCsrText(e.target.value)}
            placeholder="-----BEGIN CERTIFICATE REQUEST-----..."
            rows={6}
            className="w-full p-2 border rounded font-mono text-sm text-gray-900"
          />
        </div>

        {/* Or upload CSR file */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Or upload CSR file
          </label>
          <input
            type="file"
            accept=".csr,text/plain"
            onChange={handleFile}
            className="block w-full text-sm text-gray-900 rounded border px-2 py-1"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className={`px-4 py-2 rounded text-white ${
            loading ? 'bg-gray-400' : 'bg-green-600 hover:bg-green-700'
          }`}
        >
          {loading ? 'Registering…' : 'Register'}
        </button>
      </form>

      {certPem && (
        <div className="mt-8">
          <h2 className="text-lg font-medium text-gray-800 mb-2">
            Device Certificate
          </h2>
          <textarea
            readOnly
            rows={8}
            value={certPem}
            className="w-full p-2 border rounded font-mono text-sm text-gray-800"
          />
          <a
            href={`data:application/x-pem-file,${encodeURIComponent(certPem)}`}
            download={`${deviceId}.crt`}
            className="inline-block mt-2 text-sm text-green-600 hover:underline"
          >
            Download {deviceId}.crt
          </a>
        </div>
      )}

      {caPem && (
        <div className="mt-8">
          <h2 className="text-lg font-medium text-gray-800 mb-2">
            CA Certificate
          </h2>
          <textarea
            readOnly
            rows={4}
            value={caPem}
            className="w-full p-2 border rounded font-mono text-sm text-gray-800"
          />
          <a
            href={`data:application/x-pem-file,${encodeURIComponent(caPem)}`}
            download="ca.crt"
            className="inline-block mt-2 text-sm text-green-600 hover:underline"
          >
            Download ca.crt
          </a>
        </div>
      )}
    </div>
  );
}
