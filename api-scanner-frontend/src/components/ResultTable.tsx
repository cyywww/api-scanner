import React from "react";

type Result = {
  payload: string;
  vulnerable: boolean;
  method?: string;
  parameter?: string;
  field?: string;
  url?: string;
  confidence?: number;
  severity?: string;
  evidence?: string;
  error?: string;
  responseTime?: number;
  context?: string;
  databaseType?: string;
  injectionType?: string;
};

interface ResultTableProps {
  results: Result[];
  type: "xss" | "sql";
}

export const ResultTable: React.FC<ResultTableProps> = ({ results, type }) => {
  const getMethodColor = () => {
    if (type === "xss") return "bg-blue-100 text-blue-800";
    return "bg-purple-100 text-purple-800";
  };

  const getSeverityStyle = (severity?: string) => {
    switch (severity) {
      case "critical":
      case "high":
        return "bg-red-500 text-white";
      case "medium":
        return "bg-yellow-500 text-white";
      case "low":
        return "bg-yellow-300 text-gray-800";
      default:
        return "bg-gray-200 text-gray-600";
    }
  };

  if (results.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        <svg
          className="mx-auto h-12 w-12 text-gray-400 mb-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
          />
        </svg>
        <p>No scan results yet</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {results.map((result, index) => (
        <div
          key={index}
          className={`border rounded-lg p-4 transition-all duration-200 hover:shadow-md ${
            result.vulnerable
              ? "border-red-200 bg-red-50"
              : "border-green-200 bg-green-50"
          }`}
        >
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center mb-2 flex-wrap gap-2">
                <span
                  className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    result.vulnerable
                      ? "bg-red-100 text-red-800"
                      : "bg-green-100 text-green-800"
                  }`}
                >
                  {result.vulnerable ? "⚠️ Vulnerable" : "✓ Safe"}
                </span>
                {result.method && (
                  <span
                    className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getMethodColor()}`}
                  >
                    {result.method}
                  </span>
                )}
                {result.severity && (
                  <span
                    className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityStyle(
                      result.severity
                    )}`}
                  >
                    {result.severity.toUpperCase()}
                  </span>
                )}
              </div>

              <div className="text-sm space-y-1">
                <div className="font-mono text-gray-700">
                  <span className="font-semibold">Payload:</span>{" "}
                  <span className="text-gray-900 break-all">
                    {result.payload}
                  </span>
                </div>

                {result.parameter && (
                  <div className="text-gray-600">
                    <span className="font-semibold">Parameter:</span>{" "}
                    <span className="font-medium">{result.parameter}</span>
                  </div>
                )}

                {result.url && (
                  <div className="text-gray-600">
                    <span className="font-semibold">URL:</span>{" "}
                    <span className="font-medium break-all">{result.url}</span>
                  </div>
                )}

                {result.evidence && (
                  <div className="text-green-700">
                    <span className="font-semibold">Evidence:</span>{" "}
                    <span className="break-all">{result.evidence}</span>
                  </div>
                )}

                {result.error && (
                  <div className="text-red-600">
                    <span className="font-semibold">Error:</span>{" "}
                    <span className="break-all">{result.error}</span>
                  </div>
                )}
              </div>
            </div>

            {result.confidence && (
              <div className="ml-4 text-center flex-shrink-0">
                <div className="relative w-16 h-16">
                  <svg className="w-16 h-16 transform -rotate-90">
                    <circle
                      cx="32"
                      cy="32"
                      r="28"
                      stroke="currentColor"
                      strokeWidth="4"
                      fill="none"
                      className="text-gray-200"
                    />
                    <circle
                      cx="32"
                      cy="32"
                      r="28"
                      stroke="currentColor"
                      strokeWidth="4"
                      fill="none"
                      strokeDasharray={`${
                        (2 * Math.PI * 28 * result.confidence) / 100
                      } ${2 * Math.PI * 28}`}
                      className={
                        result.confidence >= 80
                          ? "text-green-500"
                          : result.confidence >= 60
                          ? "text-yellow-500"
                          : "text-red-500"
                      }
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-sm font-bold">
                      {result.confidence}%
                    </span>
                  </div>
                </div>
                <div className="text-xs text-gray-500 mt-1">Confidence</div>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};
