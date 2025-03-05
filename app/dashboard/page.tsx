"use client"
import { useState } from 'react';
import axios from 'axios';

export default function Home() {
  const [ip, setIp] = useState('');
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);

    try {
      const response = await axios.post('/api/scan', { ip });
      setResult(response.data);
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        setError(err.response?.data?.error || 'Something went wrong');
      } else {
        setError('Something went wrong');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex flex-col items-center justify-center p-4">
      <h1 className="text-3xl font-bold text-gray-800 mb-6">Scan IP Addresses with Umbrasec</h1>
      <form onSubmit={handleScan} className="flex flex-col sm:flex-row gap-4 w-full max-w-md">
        <input
          type="text"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="Enter IP (e.g., 8.8.8.8)"
          className="flex-1 p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          type="submit"
          disabled={loading}
          className={`px-4 py-2 rounded-md text-white font-medium ${
            loading ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'
          }`}
        >
          {loading ? 'Scanning...' : 'Scan'}
        </button>
      </form>

      {error && <p className="mt-4 text-red-600 font-medium">{error}</p>}
      {result && (
        <div className="mt-6 w-full max-w-2xl bg-white p-4 rounded-md shadow-md">
          <h2 className="text-xl font-semibold text-gray-700 mb-2">Results for {ip}</h2>
          <pre className="bg-gray-50 p-4 rounded-md text-sm text-gray-800 overflow-x-auto">
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}