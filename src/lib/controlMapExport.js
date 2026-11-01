// Flattens the current control_map state into a share-ready CSV.

const COLUMNS = [
  ['Control ID', (row) => row.control_id],
  ['Status', (row) => row.status],
  ['Requirement', (row) => row.requirement],
  ['Probe', (row) => row.probe_id],
  ['Target', (row) => row.target],
  ['Evidence Mode', (row) => row.evidence_mode],
  ['Evidence Summary', (row) => row.evidence_summary],
  ['Last Run (UTC)', (row) => formatTime(row.last_run_at)],
];

function formatTime(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
}

function cell(value) {
  const text = value === null || value === undefined ? '' : String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function buildControlCsv(rows) {
  const lines = [COLUMNS.map(([header]) => cell(header)).join(',')];
  for (const row of rows) {
    lines.push(COLUMNS.map(([, read]) => cell(read(row))).join(','));
  }
  return lines.join('\n');
}

export function downloadControlCsv(rows) {
  const csv = buildControlCsv(rows);
  const stamp = new Date().toISOString().slice(0, 10);
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `soc2-control-status-${stamp}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}