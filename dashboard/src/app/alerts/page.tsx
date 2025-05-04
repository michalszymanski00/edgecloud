// src/app/alerts/page.tsx
import React from 'react';

export default function AlertsPage() {
  // TODO: replace this with real data when /alerts exists
  const alerts: { id: string; message: string; severity: 'info' | 'warn' | 'error' }[] = [];

  return (
    <div className="p-6">
      <h1 className="text-2xl font-semibold mb-4 text-gray-900">Alerts</h1>

      <div className="bg-white shadow rounded-lg overflow-hidden">
        {alerts.length > 0 ? (
          <ul>
            {alerts.map(a => (
              <li
                key={a.id}
                className={`
                  px-4 py-3 border-b last:border-b-0
                  ${a.severity === 'error' ? 'bg-red-50 hover:bg-red-100' :
                    a.severity === 'warn'  ? 'bg-yellow-50 hover:bg-yellow-100' :
                    'bg-blue-50 hover:bg-blue-100'}
                  transition-colors
                `}
              >
                <span className="text-gray-800">
                  {a.message}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="px-4 py-6 text-gray-500">
            No alerts at the moment.
          </div>
        )}
      </div>
    </div>
  );
}
