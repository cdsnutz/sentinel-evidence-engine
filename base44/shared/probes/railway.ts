import { buildResult } from './registry.ts';

const RAILWAY_GQL = 'https://backboard.railway.app/graphql/v2';
const TIMEOUT_MS = 15000;

const SECRET_KEY_PATTERN =
  /(PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CREDENTIAL|DATABASE_URL|CONNECTION[_-]?STRING|DSN)/i;

const WEAK_VALUES = new Set([
  'password',
  'passwd',
  'admin',
  'root',
  'secret',
  'changeme',
  'change-me',
  'test',
  'dev',
  'qwerty',
  'letmein',
  'example',
  'todo',
  'null',
  'none',
]);

// Returns a reason when the value looks like weak plaintext, otherwise null.
function lookWeak(value) {
  const text = String(value ?? '').trim();
  if (!text) return null;
  if (WEAK_VALUES.has(text.toLowerCase())) return 'dictionary value';
  if (/^\d{1,8}$/.test(text)) return 'numeric PIN-length value';
  if (/^(true|false|yes|no|on|off)$/i.test(text)) return 'boolean placeholder';
  if (/^(.)\1+$/.test(text)) return 'repeated-character value';
  if (text.length < 12) return 'short plaintext value';
  return null;
}

export function probeRailwayEnvLeakage(variables, target = 'railway/service') {
  if (!variables || typeof variables !== 'object' || Array.isArray(variables)) {
    return buildResult(
      'railway_env_leakage',
      target,
      'FAIL',
      'no environment variable map was returned to scan',
      { scanned_keys: 0 },
      null,
    );
  }
  const keys = Object.keys(variables);
  if (keys.length === 0) {
    return buildResult(
      'railway_env_leakage',
      target,
      'FAIL',
      'environment variable map is empty, nothing could be verified',
      { scanned_keys: 0 },
      null,
    );
  }
  const findings = [];
  for (const key of keys) {
    if (!SECRET_KEY_PATTERN.test(key)) continue;
    const reason = lookWeak(variables[key]);
    if (reason) findings.push({ key, reason });
  }
  const passed = findings.length === 0;
  return buildResult(
    'railway_env_leakage',
    target,
    passed ? 'PASS' : 'FAIL',
    passed
      ? `no weak plaintext values across ${keys.length} variable(s)`
      : `${findings.length} secret-like variable(s) hold weak plaintext values`,
    { scanned_keys: keys.length, findings },
    null,
  );
}

export function probeRailwayBackups(settings, target = 'railway/service', maxAgeDays = 7) {
  const backups = settings?.backups ?? settings?.backup ?? null;
  if (!backups) {
    return buildResult(
      'railway_backup_freshness',
      target,
      'FAIL',
      'no backup configuration is present on the service',
      { backups_present: false },
      null,
    );
  }
  if (backups.disabled === true || backups.enabled === false) {
    return buildResult(
      'railway_backup_freshness',
      target,
      'FAIL',
      'backups are disabled for this service',
      { backups_present: true, disabled: true },
      null,
    );
  }
  const raw =
    backups.lastBackupAt ??
    backups.last_backup_at ??
    backups.latestBackupAt ??
    backups.lastSuccessfulBackupAt ??
    null;
  if (!raw) {
    return buildResult(
      'railway_backup_freshness',
      target,
      'FAIL',
      'backups are enabled but no successful backup timestamp exists',
      { backups_present: true, last_backup_at: null },
      null,
    );
  }
  const ms = new Date(raw).getTime();
  if (!Number.isFinite(ms)) {
    return buildResult(
      'railway_backup_freshness',
      target,
      'FAIL',
      'backup timestamp could not be parsed',
      { backups_present: true, last_backup_at: raw },
      null,
    );
  }
  const ageDays = (Date.now() - ms) / 86400000;
  const fresh = ageDays <= maxAgeDays;
  return buildResult(
    'railway_backup_freshness',
    target,
    fresh ? 'PASS' : 'FAIL',
    fresh
      ? `last successful backup ${ageDays.toFixed(2)} days ago`
      : `last backup is ${ageDays.toFixed(1)} days old (limit ${maxAgeDays})`,
    { backups_present: true, last_backup_at: new Date(ms).toISOString(), age_days: Number(ageDays.toFixed(2)) },
    null,
  );
}

const MANUAL_SOURCES = ['manual', 'image', 'dockerimage', 'docker', 'local'];

export function probeRailwayDeploymentTraceability(deployments, target = 'railway/service') {
  if (!Array.isArray(deployments) || deployments.length === 0) {
    return buildResult(
      'railway_deployment_traceability',
      target,
      'FAIL',
      'no deployments were returned to verify',
      { deployments_checked: 0 },
      null,
    );
  }
  const untraced = [];
  for (const deployment of deployments) {
    const meta = deployment?.meta ?? {};
    const sha = meta.commitHash ?? meta.commit ?? meta.sha ?? deployment?.commitHash ?? null;
    const source = String(meta.source ?? deployment?.source ?? '').toLowerCase();
    const manual = MANUAL_SOURCES.includes(source);
    if (!sha || manual) {
      untraced.push({
        id: deployment?.id ?? null,
        source: source || null,
        has_commit: Boolean(sha),
      });
    }
  }
  const passed = untraced.length === 0;
  return buildResult(
    'railway_deployment_traceability',
    target,
    passed ? 'PASS' : 'FAIL',
    passed
      ? `all ${deployments.length} deployment(s) link to a Git commit`
      : `${untraced.length} of ${deployments.length} deployment(s) have no Git commit trace`,
    { deployments_checked: deployments.length, untraced },
    null,
  );
}

async function railwayQuery(token, query, variables) {
  const response = await fetch(RAILWAY_GQL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ query, variables }),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  let body = null;
  try {
    body = await response.json();
  } catch (_) {
    body = null;
  }
  return { status: response.status, body };
}

const VARIABLES_QUERY = `query ProbeVariables($projectId: String!, $environmentId: String, $serviceId: String) {
  variables(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId)
}`;

const DEPLOYMENTS_QUERY = `query ProbeDeployments($projectId: String!, $environmentId: String, $serviceId: String) {
  deployments(first: 20, input: { projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId }) {
    edges { node { id status createdAt meta } }
  }
}`;

// Best-effort read: each part fails independently so one unsupported field
// cannot blind the other probes.
export async function fetchRailwaySnapshot(token, target) {
  const variables = {
    projectId: target.project_id,
    environmentId: target.environment_id ?? null,
    serviceId: target.service_id ?? null,
  };
  const errors = [];
  const [envResult, deployResult] = await Promise.allSettled([
    railwayQuery(token, VARIABLES_QUERY, variables),
    railwayQuery(token, DEPLOYMENTS_QUERY, variables),
  ]);

  let envMap = null;
  if (envResult.status === 'fulfilled') {
    if (envResult.value.status >= 400) errors.push(`variables HTTP ${envResult.value.status}`);
    if (envResult.value.body?.errors?.length) errors.push(`variables: ${envResult.value.body.errors[0].message}`);
    const data = envResult.value.body?.data?.variables;
    if (data && typeof data === 'object' && !Array.isArray(data)) envMap = data;
  } else {
    errors.push(`variables: ${envResult.reason?.message ?? 'request failed'}`);
  }

  let deployments = null;
  if (deployResult.status === 'fulfilled') {
    if (deployResult.value.status >= 400) errors.push(`deployments HTTP ${deployResult.value.status}`);
    if (deployResult.value.body?.errors?.length) errors.push(`deployments: ${deployResult.value.body.errors[0].message}`);
    const edges = deployResult.value.body?.data?.deployments?.edges;
    if (Array.isArray(edges)) deployments = edges.map((edge) => edge?.node).filter(Boolean);
  } else {
    errors.push(`deployments: ${deployResult.reason?.message ?? 'request failed'}`);
  }

  return { variables: envMap, deployments, errors };
}