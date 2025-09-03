import { useState } from 'react';
import { scanXSS, scanSQLInjection } from '../services/api';
import { ResultTable } from '../components/ResultTable';

export default function Home() {
  const [url, setUrl] = useState('');
  const [xssResults, setXssResults] = useState([]);
  const [sqlResults, setSqlResults] = useState([]);
  const [xssLoading, setXssLoading] = useState(false);
  const [sqlLoading, setSqlLoading] = useState(false);

  const handleXSSScan = async () => {
    setXssLoading(true);
    try {
      const data = await scanXSS(url);
      setXssResults(data);
    } catch (err) {
      console.error(err);
    } finally {
      setXssLoading(false);
    }
  };

  const handleSQLScan = async () => {
    setSqlLoading(true);
    try {
      const data = await scanSQLInjection(url);
      setSqlResults(data);
    } catch (err) {
      console.error(err);
    } finally {
      setSqlLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center py-12 px-4">
      <div className="max-w-4xl w-full space-y-8">
        {/* URL Input Area */}
        <div className="bg-white rounded-2xl shadow-sm p-8">
          <h1 className="text-3xl font-semibold text-gray-800 mb-6 tracking-wide text-center">
            Security Scanner
          </h1>

          <input
            type="text"
            placeholder="Enter target URL"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="border border-gray-300 focus:border-gray-500 focus:ring-1 focus:ring-gray-300 
                       rounded-lg px-4 py-2 w-full text-gray-700 placeholder-gray-400 outline-none"
          />
        </div>

        <div className="grid md:grid-cols-2 gap-6">
          {/* Scan XSS */}
          <div className="bg-white rounded-2xl shadow-sm p-8">
            <h2 className="text-2xl font-semibold text-gray-800 mb-4 tracking-wide text-center">
              XSS Scanner
            </h2>

            <button
              onClick={handleXSSScan}
              disabled={xssLoading || !url.trim()}
              className={`w-full py-2.5 rounded-lg text-white font-medium transition-colors 
                ${xssLoading || !url.trim()
                  ? 'bg-gray-400 cursor-not-allowed' 
                  : 'bg-red-600 hover:bg-red-700'}`}
            >
              {xssLoading ? 'Scanning XSS...' : 'Start XSS Scan'}
            </button>

            {xssResults.length > 0 && (
              <div className="mt-6">
                <h3 className="text-lg font-medium text-gray-700 mb-3">XSS Scan Results</h3>
                <ResultTable results={xssResults} />
              </div>
            )}
          </div>

          {/* Scan SQL injection! */}
          <div className="bg-white rounded-2xl shadow-sm p-8">
            <h2 className="text-2xl font-semibold text-gray-800 mb-4 tracking-wide text-center">
              SQL Injection Scanner
            </h2>

            <button
              onClick={handleSQLScan}
              disabled={sqlLoading || !url.trim()}
              className={`w-full py-2.5 rounded-lg text-white font-medium transition-colors 
                ${sqlLoading || !url.trim()
                  ? 'bg-gray-400 cursor-not-allowed' 
                  : 'bg-blue-600 hover:bg-blue-700'}`}
            >
              {sqlLoading ? 'Scanning SQL...' : 'Start SQL Injection Scan'}
            </button>

            {sqlResults.length > 0 && (
              <div className="mt-6">
                <h3 className="text-lg font-medium text-gray-700 mb-3">SQL Injection Results</h3>
                <ResultTable results={sqlResults} />
              </div>
            )}
          </div>
        </div>

        {/* Scan all! */}
        <div className="bg-white rounded-2xl shadow-sm p-8">
          <button
            onClick={async () => {
              await Promise.all([handleXSSScan(), handleSQLScan()]);
            }}
            disabled={xssLoading || sqlLoading || !url.trim()}
            className={`w-full py-3 rounded-lg text-white font-medium transition-colors text-lg
              ${xssLoading || sqlLoading || !url.trim()
                ? 'bg-gray-400 cursor-not-allowed' 
                : 'bg-gradient-to-r from-red-600 to-blue-600 hover:from-red-700 hover:to-blue-700'}`}
          >
            {xssLoading || sqlLoading ? 'Scanning...' : 'Run All Security Scans'}
          </button>
        </div>
      </div>
    </div>
  );
}