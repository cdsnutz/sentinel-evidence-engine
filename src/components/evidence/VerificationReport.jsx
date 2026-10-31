import StatusChip from '@/components/evidence/StatusChip';

function Artifact({ title, mode, proven, payload }) {
  return (
    <div className="border border-zinc-800">
      <div className="flex items-center justify-between border-b border-zinc-800 bg-zinc-950 px-3 py-2">
        <span className="text-[10px] tracking-[0.2em] text-zinc-500">{title}</span>
        <span className="flex items-center gap-2">
          {mode && (
            <span className="text-[10px] uppercase tracking-widest text-zinc-600">{mode}</span>
          )}
          <StatusChip status={proven ? 'PASS' : 'FAIL'} />
        </span>
      </div>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words px-3 py-3 text-[11px] leading-relaxed text-zinc-400">
        {JSON.stringify(payload, null, 2)}
      </pre>
    </div>
  );
}

export default function VerificationReport({ report }) {
  if (!report) {
    return (
      <section className="mt-8 border border-dashed border-zinc-800 px-4 py-6 text-xs text-zinc-600">
        No report generated yet. Run the harness to produce the success log, the failure log and
        the control_map dump.
      </section>
    );
  }

  const { artifacts = {}, logic_suite = [], notes = [] } = report;

  return (
    <section className="mt-8 space-y-4">
      <header className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-[11px] tracking-[0.24em] text-zinc-500">VERIFICATION_REPORT</h2>
        <span className="text-[11px] text-zinc-600">{report.generated_at}</span>
      </header>

      <Artifact
        title="1 · SUCCESS_LOG"
        mode={artifacts.success_log?.mode}
        proven={Boolean(artifacts.success_log?.proven)}
        payload={artifacts.success_log ?? { status: 'missing' }}
      />
      <Artifact
        title="2 · FAILURE_LOG"
        mode={artifacts.failure_log?.mode}
        proven={Boolean(artifacts.failure_log?.proven)}
        payload={artifacts.failure_log ?? { status: 'missing' }}
      />
      <Artifact
        title="3 · DATABASE_STATE"
        mode="control_map"
        proven={Boolean(artifacts.database_state?.proven)}
        payload={artifacts.database_state ?? { status: 'missing' }}
      />

      <div className="border border-zinc-800">
        <div className="border-b border-zinc-800 bg-zinc-950 px-3 py-2 text-[10px] tracking-[0.2em] text-zinc-500">
          LOGIC_SUITE · PURE FUNCTION PROOFS
        </div>
        <ul className="divide-y divide-zinc-900">
          {logic_suite.map((item) => (
            <li key={item.case} className="flex items-center justify-between gap-4 px-3 py-2 text-[11px]">
              <span className="text-zinc-400">{item.case}</span>
              <span className="flex items-center gap-3">
                <span className="text-zinc-600">expected {item.expected}</span>
                <StatusChip status={item.matched ? 'PASS' : 'FAIL'} />
              </span>
            </li>
          ))}
        </ul>
      </div>

      {notes.length > 0 && (
        <ul className="space-y-1 text-[11px] leading-relaxed text-zinc-600">
          {notes.map((note) => (
            <li key={note}>— {note}</li>
          ))}
        </ul>
      )}
    </section>
  );
}