import { useState } from 'react';
import { scanXSS } from '../services/api';
import { ResultTable } from '../components/ResultTable';

export default function Home() {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    setLoading(true);
    try {
      const data = await scanXSS(url);
      setResults(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto py-10">
      <h1 className="text-2xl font-bold mb-4">🛡️ XSS Security Scanner</h1>
      <input
        type="text"
        placeholder="Enter target URL"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        className="border p-2 w-full mb-4"
      />
      <button
        onClick={handleScan}
        disabled={loading}
        className="bg-blue-600 text-white px-4 py-2 rounded"
      >
        {loading ? 'Scanning...' : 'Start XSS Scan'}
      </button>

      {results.length > 0 && <ResultTable results={results} />}
    </div>
  );
}