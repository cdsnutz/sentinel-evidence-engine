import { Download } from 'lucide-react';
import { downloadControlCsv } from '@/lib/controlMapExport';

export default function ExportControlMap({ rows }) {
  const empty = rows.length === 0;

  return (
    <button
      type="button"
      onClick={() => downloadControlCsv(rows)}
      disabled={empty}
      title={empty ? 'No control rows to export yet' : 'Download the current control status as CSV'}
      className="inline-flex items-center gap-2 border border-zinc-700 bg-zinc-900 px-4 py-2 text-[11px] tracking-[0.16em] text-zinc-300 transition hover:border-zinc-600 hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-40"
    >
      <Download className="h-3.5 w-3.5" />
      EXPORT STATUS
    </button>
  );
}