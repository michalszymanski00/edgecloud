'use client';

import { useState, useEffect } from 'react';

export default function APIConfigPage() {
  // Initialize from env or localStorage
  const [baseUrl, setBaseUrl]     = useState(
    () => localStorage.getItem('apiUrl')     || process.env.NEXT_PUBLIC_API_URL || ''
  );
  const [enrollUrl, setEnrollUrl] = useState(
    () => localStorage.getItem('enrollUrl')  || process.env.NEXT_PUBLIC_ENROLL_URL || ''
  );

  function onSave() {
    localStorage.setItem('apiUrl', baseUrl);
    localStorage.setItem('enrollUrl', enrollUrl);
    alert('Configuration saved locally!');
  }

  return (
    <div className="p-6">
      <h1 className="text-2xl font-semibold mb-6 text-gray-900">
        API Configuration
      </h1>
      <div className="space-y-6 max-w-md">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Base URL
          </label>
          <input
            type="text"
            value={baseUrl}
            onChange={e => setBaseUrl(e.target.value)}
            className="w-full px-3 py-2 border rounded focus:outline-none focus:ring"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Enrollment URL
          </label>
          <input
            type="text"
            value={enrollUrl}
            onChange={e => setEnrollUrl(e.target.value)}
            className="w-full px-3 py-2 border rounded focus:outline-none focus:ring"
          />
        </div>
        <button
          onClick={onSave}
          className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
        >
          Save
        </button>
      </div>
    </div>
  );
}
