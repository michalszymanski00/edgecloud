// src/app/settings/page.tsx
import React from 'react';
import Link from 'next/link';

export default function SettingsPage() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-semibold mb-6 text-gray-900">Settings</h1>

      <nav className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Admin Tokens */}
        <Link
          href="/settings/tokens"
          className="block bg-white shadow rounded-lg p-6 hover:bg-gray-50 transition"
        >
          <h2 className="text-lg font-medium text-gray-800 mb-2">Admin Tokens</h2>
          <p className="text-sm text-gray-600">
            Create, view, and revoke API access tokens.
          </p>
        </Link>

        {/* API Configuration */}
        <Link
          href="/settings/api"
          className="block bg-white shadow rounded-lg p-6 hover:bg-gray-50 transition"
        >
          <h2 className="text-lg font-medium text-gray-800 mb-2">API Configuration</h2>
          <p className="text-sm text-gray-600">
            Base URL: <code className="font-mono">{process.env.NEXT_PUBLIC_API_URL}</code>
          </p>
        </Link>

        {/* Registration Token (read-only) */}
        <div className="bg-white shadow rounded-lg p-6">
          <h2 className="text-lg font-medium text-gray-800 mb-2">Registration Token</h2>
          <p className="text-sm font-mono text-gray-700 break-all bg-gray-50 p-3 rounded">
            {process.env.NEXT_PUBLIC_REG_TOKEN}
          </p>
        </div>

        {/* Register Device */}
        <Link
          href="/settings/register"
          className="block bg-white shadow rounded-lg p-6 hover:bg-gray-50 transition"
        >
          <h2 className="text-lg font-medium text-gray-800 mb-2">Register Device</h2>
          <p className="text-sm text-gray-600">
            Upload a CSR to obtain a signed device certificate and CA bundle.
          </p>
        </Link>
      </nav>
    </div>
  );
}
