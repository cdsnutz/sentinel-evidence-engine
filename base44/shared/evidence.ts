function readRows(response) {
  return Array.isArray(response) ? response : (response?.items ?? []);
}

// One probe -> one immutable evidence row, plus the live truth-table row.
async function applyResult(base44, result, meta) {
  const db = base44.asServiceRole.entities;
  const ranAt = new Date().toISOString();

  await db.ProbeRun.create({
    probe_id: result.probe_id,
    control_id: result.control_id,
    provider: result.provider,
    target: result.target,
    status: result.status,
    reason: result.reason,
    evidence: result.evidence ?? {},
    http_status: typeof result.http_status === 'number' ? result.http_status : null,
    mode: meta.mode,
    token_source: meta.token_source ?? 'none',
    duration_ms: meta.duration_ms ?? 0,
    ran_at: ranAt,
  });

  const controlPatch = {
    control_id: result.control_id,
    probe_id: result.probe_id,
    requirement: result.requirement,
    provider: result.provider,
    target: result.target,
    status: result.status,
    evidence_mode: meta.mode,
    evidence_summary: result.reason,
    last_run_at: ranAt,
  };

  const existing = readRows(
    await db.ControlMap.filter({ probe_id: result.probe_id, target: result.target }, { limit: 1 }),
  );

  if (existing.length > 0) {
    await db.ControlMap.update(existing[0].id, controlPatch);
  } else {
    await db.ControlMap.create(controlPatch);
  }

  return {
    probe_id: result.probe_id,
    control_id: result.control_id,
    target: result.target,
    status: result.status,
    mode: meta.mode,
  };
}

export async function persistResults(base44, results, meta) {
  const settled = await Promise.allSettled(
    results.map((result) => applyResult(base44, result, meta)),
  );
  return settled.map((entry, index) => {
    if (entry.status === 'fulfilled') return entry.value;
    return {
      probe_id: results[index].probe_id,
      target: results[index].target,
      status: results[index].status,
      persisted: false,
      error: String(entry.reason?.message ?? entry.reason),
    };
  });
}