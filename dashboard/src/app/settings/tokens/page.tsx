'use client';

import { useEffect, useState } from 'react';
import { fetchTokens, createToken, deleteToken } from '@/lib/api';
import { Trash2, Plus } from 'lucide-react';

type Token = {
  device_id: string;
  token:     string;
};

export default function TokensPage() {
  const [tokens, setTokens]   = useState<Token[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    load();
  }, []);

  async function load() {
    try {
      const list = await fetchTokens();  // now returns Token[]
      setTokens(list);
    } catch (err: any) {
      console.error('failed to fetch tokens:', err);
      alert(`Error fetching tokens:\n${JSON.stringify(err.response?.data || err)}`);
    }
  }
  
  async function onCreate() {
    setLoading(true);
    try {
      const newToken = await createToken(); // { device_id, token }
      alert(`New token for ${newToken.device_id}: ${newToken.token}`);
      await load();
    } catch (err: any) {
      console.error('failed to create token:', err);
      alert(`Error creating token:\n${JSON.stringify(err.response?.data || err)}`);
    } finally {
      setLoading(false);
    }
  }

  async function onDelete(token: string) {
    if (!confirm('Revoke this token?')) return;
    await deleteToken(token);
    await load();
  }

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-semibold text-gray-900">Device Tokens</h1>
        <button
          className="flex items-center bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700"
          onClick={onCreate}
          disabled={loading}
        >
          <Plus className="mr-1" size={16} /> New Token
        </button>
      </div>

      <div className="bg-white shadow rounded-lg overflow-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase">
                Device ID
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase">
                Token
              </th>
              <th className="px-6 py-3 w-16" />
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {tokens.map((t, idx) => (
              <tr key={`${t.device_id}-${idx}`}>
                <td className="px-6 py-4 text-sm text-gray-900">{t.device_id}</td>
                <td className="px-6 py-4 text-sm text-gray-700 font-mono break-all">
                  {t.token}
                </td>
                <td className="px-6 py-4 text-right">
                  <button
                    onClick={() => onDelete(t.token)}
                    className="text-red-600 hover:text-red-800"
                  >
                    <Trash2 size={16} />
                  </button>
                </td>
              </tr>
            ))}
            {tokens.length === 0 && (
              <tr key="no-tokens">
                <td colSpan={3} className="px-6 py-4 text-center text-gray-500">
                  No tokens found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
