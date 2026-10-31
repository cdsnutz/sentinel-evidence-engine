import { PROBE_SPEC } from '@/lib/probeSpec';

export default function ProbeInventory() {
  return (
    <section className="mt-10">
      <header className="mb-3 flex items-baseline justify-between">
        <h2 className="text-[11px] tracking-[0.24em] text-zinc-500">PROBE_INVENTORY</h2>
        <span className="text-[11px] text-zinc-600">{PROBE_SPEC.length} probes · read-only</span>
      </header>
      <ul className="divide-y divide-zinc-900 border border-zinc-800">
        {PROBE_SPEC.map((probe) => (
          <li key={probe.probe_id} className="flex flex-wrap items-baseline gap-x-4 gap-y-1 px-3 py-2.5">
            <span className="w-20 shrink-0 text-[10px] uppercase tracking-widest text-zinc-600">
              {probe.provider}
            </span>
            <span className="text-xs text-zinc-300">{probe.probe_id}</span>
            <span className="text-[10px] tracking-widest text-zinc-600">{probe.control_id}</span>
            <span className="w-full text-[11px] text-zinc-600 sm:w-auto sm:flex-1">{probe.requirement}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}