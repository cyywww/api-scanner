type Result = {
  payload: string;
  vulnerable: boolean;
  error?: string;
};

export const ResultTable = ({ results }: { results: Result[] }) => {
  return (
    <table className="w-full mt-4 border">
      <thead>
        <tr className="bg-gray-100">
          <th className="p-2 border">Payload</th>
          <th className="p-2 border">Vulnerable</th>
          <th className="p-2 border">Error</th>
        </tr>
      </thead>
      <tbody>
        {results.map((r, i) => (
          <tr key={i} className="border">
            <td className="p-2 border">{r.payload}</td>
            <td className="p-2 border">{r.vulnerable ? "✅" : "❌"}</td>
            <td className="p-2 border">{r.error ?? "-"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};