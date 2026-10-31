const TONE = {
  PASS: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
  FAIL: 'border-rose-400/30 bg-rose-400/10 text-rose-300',
  PENDING: 'border-zinc-600/50 bg-zinc-500/10 text-zinc-500',
};

export default function StatusChip({ status = 'PENDING', className = '' }) {
  const key = status === 'PASS' || status === 'FAIL' ? status : 'PENDING';
  return (
    <span
      className={`inline-flex items-center rounded-sm border px-2 py-0.5 text-[10px] tracking-[0.18em] ${TONE[key]} ${className}`}
    >
      {key}
    </span>
  );
}