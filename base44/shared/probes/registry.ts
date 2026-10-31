// Single source of truth for probe -> SOC2 control mapping.
export const PROBE_REGISTRY = [
  {
    probe_id: 'github_branch_protection',
    control_id: 'SOC2-CC8.1',
    provider: 'github',
    requirement: 'Default branch must be protected against force-push and deletion',
  },
  {
    probe_id: 'github_required_signatures',
    control_id: 'SOC2-CC7.1',
    provider: 'github',
    requirement: 'Commits merged to the default branch must be cryptographically signed',
  },
  {
    probe_id: 'github_admin_access_review',
    control_id: 'SOC2-CC6.3',
    provider: 'github',
    requirement: 'Every admin collaborator must carry a Security review tag',
  },
  {
    probe_id: 'railway_backup_freshness',
    control_id: 'SOC2-A1.2',
    provider: 'railway',
    requirement: 'Service backups must be enabled with a recent successful backup',
  },
  {
    probe_id: 'railway_env_leakage',
    control_id: 'SOC2-CC6.1',
    provider: 'railway',
    requirement: 'Environment variables must not hold weak or plaintext secrets',
  },
  {
    probe_id: 'railway_deployment_traceability',
    control_id: 'SOC2-CC8.1',
    provider: 'railway',
    requirement: 'Every production deployment must trace to a Git commit hash',
  },
];

export function probeSpec(probeId) {
  const spec = PROBE_REGISTRY.find((entry) => entry.probe_id === probeId);
  if (!spec) throw new Error(`unknown probe: ${probeId}`);
  return spec;
}

export function buildResult(probeId, target, status, reason, evidence, httpStatus) {
  const spec = probeSpec(probeId);
  return {
    probe_id: spec.probe_id,
    control_id: spec.control_id,
    requirement: spec.requirement,
    provider: spec.provider,
    target,
    status,
    reason,
    evidence: evidence ?? {},
    http_status: typeof httpStatus === 'number' ? httpStatus : null,
  };
}