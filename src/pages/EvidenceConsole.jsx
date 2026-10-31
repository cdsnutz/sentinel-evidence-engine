import { useCallback, useEffect, useMemo, useState } from 'react';
import { base44 } from '@/api/base44Client';
import { AlertTriangle, Loader2, Play } from 'lucide-react';
import StatusChip from '@/components/evidence/StatusChip';
import ControlMapTable from '@/components/evidence/ControlMapTable';
import VerificationReport from '@/components/evidence/VerificationReport';
import ProbeInventory from '@/components/evidence/ProbeInventory';

export default function EvidenceConsole() {
  const [rows, setRows] = useState([]);
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const loadRows = useCallback(async () => {
    const page = await base44.entities.ControlMap.list({ sort: 'control_id', limit: 200 });
    setRows(page?.items ?? []);
  }, []);

  useEffect(() => {
    loadRows().catch((e) => setError(e?.message ?? 'control_map read failed'));
  }, [loadRows]);

  const counts = useMemo(() => {
    const pass = rows.filter((r) => r.status === 'PASS').length;
    const fail = rows.filter((r) => r.status === 'FAIL').length;
    return { pass, fail, pending: rows.length - pass - fail };
  }, [rows]);

  const lastRun = useMemo(() => {
    const times = rows.map((r) => new Date(r.last_run_at ?? 0).getTime()).filter((t) => !Number.isNaN(t));
    if (times.length === 0) return 'never';
    return new Date(Math.max(...times)).toISOString().replace('T', ' ').slice(0, 19) + 'Z';
  }, [rows]);

  const runHarness = async () => {
    setBusy(true);
    setError(null);
    try {
      const response = await base44.functions.invoke('verifyEvidenceEngine', {});
      setReport(response.data);
      await loadRows();
    } catch (e) {
      setError(e?.response?.data?.error ?? e?.message ?? 'harness failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#08090b] font-mono text-zinc-300">
      <div className="mx-auto max-w-6xl px-5 py-10 sm:px-8">
        <header className="flex flex-wrap items-end justify-between gap-4 border-b border-zinc-800 pb-6">
          <div>
            <p className="text-[10px] tracking-[0.3em] text-zinc-600">SOVEREIGN / EVIDENCE ENGINE</p>
            <h1 className="mt-2 text-xl font-normal tracking-tight text-zinc-100">
              The Probe Army
            </h1>
            <p className="mt-1 text-[11px] text-zinc-600">
              read-only probes · github + railway · SOC2 control mapping
            </p>
          </div>
          <button
            type="button"
            onClick={runHarness}
            disabled={busy}
            className="inline-flex items-center gap-2 border border-emerald-400/30 bg-emerald-400/10 px-4 py-2 text-[11px] tracking-[0.16em] text-emerald-300 transition hover:bg-emerald-400/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
            {busy ? 'RUNNING' : 'RUN VERIFICATION'}
          </button>
        </header>

        <dl className="mt-6 grid grid-cols-2 gap-px border border-zinc-800 bg-zinc-800 sm:grid-cols-4">
          {[
            ['PASS', counts.pass, <StatusChip key="p" status="PASS" />],
            ['FAIL', counts.fail, <StatusChip key="f" status="FAIL" />],
            ['PENDING', counts.pending, <StatusChip key="n" status="PENDING" />],
            ['LAST RUN', lastRun, null],
          ].map(([label, value, chip]) => (
            <div key={label} className="bg-[#08090b] px-4 py-3">
              <dt className="text-[10px] tracking-[0.2em] text-zinc-600">{label}</dt>
              <dd className="mt-1 flex items-center gap-2 text-sm text-zinc-200">
                {chip ?? <span className="text-[11px]">{value}</span>}
                {chip ? <span>{value}</span> : null}
              </dd>
            </div>
          ))}
        </dl>

        {error && (
          <div className="mt-6 flex items-start gap-2 border border-rose-400/30 bg-rose-400/5 px-3 py-2 text-[11px] text-rose-300">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span className="break-words">{error}</span>
          </div>
        )}

        <VerificationReport report={report} />
        <ControlMapTable rows={rows} />
        <ProbeInventory />
      </div>
    </div>
  );
}