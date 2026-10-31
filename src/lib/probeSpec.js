// Display spec for the probe inventory. The authoritative registry lives in the
// probe engine; once control_map has rows, those values are shown from the database.
export const PROBE_SPEC = [
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