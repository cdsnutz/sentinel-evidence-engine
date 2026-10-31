import StatusChip from '@/components/evidence/StatusChip';

function formatTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
}

export default function ControlMapTable({ rows, live = false }) {
  return (
    <section className="mt-10">
      <header className="mb-3 flex items-baseline justify-between gap-3">
        <h2 className="flex items-center gap-2 text-[11px] tracking-[0.24em] text-zinc-500">
          CONTROL_MAP
          <span
            className={`inline-flex items-center gap-1 text-[9px] tracking-[0.18em] ${
              live ? 'text-emerald-400' : 'text-zinc-700'
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                live ? 'animate-pulse bg-emerald-400' : 'bg-zinc-700'
              }`}
            />
            LIVE
          </span>
        </h2>
        <span className="text-[11px] text-zinc-600">{rows.length} rows</span>
      </header>

      {rows.length === 0 ? (
        <p className="border border-dashed border-zinc-800 px-4 py-6 text-xs text-zinc-600">
          control_map is empty. Run the verification harness to populate it.
        </p>
      ) : (
        <div className="overflow-x-auto border border-zinc-800">
          <table className="w-full min-w-[880px] text-left text-xs">
            <thead className="bg-zinc-950 text-[10px] tracking-[0.16em] text-zinc-500">
              <tr>
                <th className="px-3 py-2 font-normal">CONTROL_ID</th>
                <th className="px-3 py-2 font-normal">PROBE_ID</th>
                <th className="px-3 py-2 font-normal">TARGET</th>
                <th className="px-3 py-2 font-normal">REQUIREMENT</th>
                <th className="px-3 py-2 font-normal">STATUS</th>
                <th className="px-3 py-2 font-normal">MODE</th>
                <th className="px-3 py-2 font-normal">LAST_RUN</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} className="border-t border-zinc-900 hover:bg-zinc-900/40">
                  <td className="whitespace-nowrap px-3 py-2 text-zinc-300">{row.control_id}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-zinc-400">{row.probe_id}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-zinc-500">{row.target || '—'}</td>
                  <td className="px-3 py-2 text-zinc-500">{row.requirement}</td>
                  <td className="px-3 py-2"><StatusChip status={row.status} /></td>
                  <td className="whitespace-nowrap px-3 py-2 text-[10px] uppercase tracking-widest text-zinc-600">
                    {row.evidence_mode || '—'}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-zinc-600">{formatTime(row.last_run_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}