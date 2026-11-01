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

// A schedule cadence implies the freshness window its backups must meet.
const FRESHNESS_WINDOW_HOURS = { DAILY: 26, WEEKLY: 192, MONTHLY: 768 };
const WINDOW_ORDER = ['DAILY', 'WEEKLY', 'MONTHLY'];

function scheduleKind(schedule) {
  const label = String(schedule?.kind ?? schedule?.name ?? '').toUpperCase();
  if (label.includes('DAILY')) return 'DAILY';
  if (label.includes('WEEKLY')) return 'WEEKLY';
  if (label.includes('MONTHLY')) return 'MONTHLY';
  const cron = String(schedule?.cron ?? '').trim().split(/\s+/);
  if (cron.length === 5) {
    const [, , dayOfMonth, , dayOfWeek] = cron;
    if (dayOfWeek !== '*' && dayOfMonth === '*') return 'WEEKLY';
    if (dayOfMonth !== '*' && dayOfWeek === '*') return 'MONTHLY';
    if (dayOfWeek === '*' && dayOfMonth === '*') return 'DAILY';
  }
  return null;
}

// The tightest cadence wins, so a daily schedule is held to the daily window.
function freshnessWindow(kinds) {
  for (const kind of WINDOW_ORDER) {
    if (kinds.includes(kind)) return { kind, hours: FRESHNESS_WINDOW_HOURS[kind] };
  }
  return null;
}

function evaluateVolumeBackup(volume) {
  const rawSchedules = Array.isArray(volume?.schedules) ? volume.schedules : [];
  const schedules = rawSchedules.map((schedule) => ({
    name: schedule?.name ?? null,
    kind: scheduleKind(schedule),
    cron: schedule?.cron ?? null,
    retention_seconds: schedule?.retentionSeconds ?? null,
  }));
  const backups = (Array.isArray(volume?.backups) ? volume.backups : [])
    .map((backup) => ({ name: backup?.name ?? null, at: new Date(backup?.createdAt).getTime() }))
    .filter((backup) => Number.isFinite(backup.at))
    .sort((a, b) => b.at - a.at);
  const window = freshnessWindow([...new Set(schedules.map((s) => s.kind).filter(Boolean))]);
  const latest = backups[0] ?? null;
  const volumeId = volume?.volume_instance_id ?? null;

  const evidence = {
    volume_instance_id: volumeId,
    mount_path: volume?.mount_path ?? null,
    schedules,
    backup_count: backups.length,
    last_backup_name: latest?.name ?? null,
    last_backup_created_at: latest ? new Date(latest.at).toISOString() : null,
    freshness_window_hours: window?.hours ?? null,
  };

  if (schedules.length === 0) {
    return { status: 'FAIL', reason: `no schedule configured on volume instance ${volumeId}`, evidence };
  }
  if (!window) {
    return { status: 'FAIL', reason: `schedule cadence could not be interpreted on volume instance ${volumeId}`, evidence };
  }
  if (!latest) {
    return { status: 'FAIL', reason: `no backup recorded for volume instance ${volumeId}`, evidence };
  }
  const ageHours = (Date.now() - latest.at) / 3600000;
  if (ageHours > window.hours) {
    return {
      status: 'FAIL',
      reason: `no backup inside the ${window.hours}h window for volume instance ${volumeId} (latest "${latest.name}" is ${ageHours.toFixed(1)}h old)`,
      evidence: { ...evidence, backup_age_hours: Number(ageHours.toFixed(2)) },
    };
  }
  return {
    status: 'PASS',
    reason: `${window.kind.toLowerCase()} schedule active on volume instance ${volumeId}, latest backup "${latest.name}" is ${ageHours.toFixed(2)}h old (window ${window.hours}h)`,
    evidence: { ...evidence, backup_age_hours: Number(ageHours.toFixed(2)) },
  };
}

// Pure decision over the volume snapshot: Railway's projectCompliance.serviceBackups
// reports an empty array even when schedules and backups exist, so the volume
// instance, its schedules and its backup list are the authoritative signals.
export function probeRailwayBackups(snapshot, target = 'railway/service', options = {}) {
  const compliance = snapshot?.compliance_signal ?? null;
  const selection = snapshot?.selection ?? null;
  const serviceId = selection?.service_id ?? options.service_id ?? null;
  const emptyEvidence = {
    volume_instance_id: null,
    schedules: [],
    backup_count: 0,
    last_backup_name: null,
    last_backup_created_at: null,
    freshness_window_hours: null,
  };

  if (!snapshot || !Array.isArray(snapshot.volumes)) {
    return buildResult(
      'railway_backup_freshness',
      target,
      'FAIL',
      `volume backup state could not be read${snapshot?.errors?.length ? `: ${snapshot.errors[0]}` : ''}`,
      { ...emptyEvidence, compliance_signal: compliance, selection },
      null,
    );
  }

  if (snapshot.volumes.length === 0) {
    const lookupFailed = snapshot.errors?.length > 0;
    return buildResult(
      'railway_backup_freshness',
      target,
      'FAIL',
      lookupFailed
        ? `volume lookup failed for service ${serviceId ?? 'unknown'}: ${snapshot.errors[0]}`
        : `volume instance not found for service ${serviceId ?? 'unknown'}`,
      { ...emptyEvidence, compliance_signal: compliance, selection },
      null,
    );
  }

  const evaluated = snapshot.volumes.map((volume) => ({
    ...evaluateVolumeBackup(volume),
    service_id: volume?.service_id ?? null,
  }));
  const passing = evaluated.find((entry) => entry.status === 'PASS');
  const chosen = passing ?? evaluated[0];

  return buildResult(
    'railway_backup_freshness',
    target,
    passing ? 'PASS' : 'FAIL',
    chosen.reason,
    {
      ...chosen.evidence,
      compliance_signal: compliance,
      selection,
      volumes_evaluated: evaluated.map((entry) => ({
        volume_instance_id: entry.evidence.volume_instance_id,
        service_id: entry.service_id,
        status: entry.status,
        reason: entry.reason,
      })),
    },
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

const PROJECT_QUERY = `query ProbeProject($id: String!) {
  project(id: $id) {
    id
    name
    environments { edges { node { id name } } }
    services { edges { node { id name } } }
  }
}`;

const VARIABLES_QUERY = `query ProbeVariables($projectId: String!, $environmentId: String!, $serviceId: String!) {
  variables(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId)
}`;

const DEPLOYMENTS_QUERY = `query ProbeDeployments($projectId: String!, $environmentId: String!, $serviceId: String!) {
  deployments(first: 20, input: { projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId }) {
    edges { node { id status createdAt meta } }
  }
}`;

const VOLUME_INSTANCES_QUERY = `query ProbeVolumes($environmentId: String!) {
  environment(id: $environmentId) {
    volumeInstances { edges { node { id serviceId volumeId mountPath currentSizeMB } } }
  }
}`;

const BACKUP_SCHEDULES_QUERY = `query ProbeBackupSchedules($volumeInstanceId: String!) {
  volumeInstanceBackupScheduleList(volumeInstanceId: $volumeInstanceId) {
    id name cron kind retentionSeconds createdAt
  }
}`;

const BACKUP_LIST_QUERY = `query ProbeBackupList($volumeInstanceId: String!) {
  volumeInstanceBackupList(volumeInstanceId: $volumeInstanceId) {
    id name createdAt scheduleId usedMB
  }
}`;

const COMPLIANCE_QUERY = `query ProbeCompliance($projectId: String!) {
  projectCompliance(projectId: $projectId) { serviceBackups { serviceId serviceName schedules } }
}`;

// Best-effort read: each part fails independently so one unsupported field
// cannot blind the other probes.
export async function fetchRailwaySnapshot(token, target) {
  const errors = [];
  let environmentId = target.environment_id || null;
  let serviceId = target.service_id || null;
  let discovered = null;

  // A project-level asset resolves its own production environment and service.
  if (!environmentId || !serviceId) {
    const discovery = await railwayQuery(token, PROJECT_QUERY, { id: target.project_id });
    if (discovery.status >= 400) errors.push(`project HTTP ${discovery.status}`);
    if (discovery.body?.errors?.length) errors.push(`project: ${discovery.body.errors[0].message}`);
    const environments = (discovery.body?.data?.project?.environments?.edges ?? [])
      .map((edge) => edge?.node)
      .filter(Boolean);
    const services = (discovery.body?.data?.project?.services?.edges ?? [])
      .map((edge) => edge?.node)
      .filter(Boolean);
    const preferredEnvironment = environments.find((env) => /prod/i.test(env?.name ?? '')) ?? environments[0] ?? null;
    if (!environmentId) environmentId = preferredEnvironment?.id ?? null;
    if (!serviceId) serviceId = services[0]?.id ?? null;
    discovered = {
      environment: preferredEnvironment?.name ?? null,
      service: services[0]?.name ?? null,
      environments_found: environments.length,
      services_found: services.length,
    };
  }

  if (!environmentId || !serviceId) {
    return {
      variables: null,
      deployments: null,
      backups: {
        volumes: [],
        compliance_signal: null,
        selection: { service_id: null, environment_id: null, mode: 'none' },
        errors: ['environment and service could not be resolved for this project'],
      },
      errors: [...errors, 'environment and service could not be resolved for this project'],
      discovered,
      environment_id: null,
      service_id: null,
    };
  }

  const variables = { projectId: target.project_id, environmentId, serviceId };
  const [envResult, deployResult, volumeResult, complianceResult] = await Promise.allSettled([
    railwayQuery(token, VARIABLES_QUERY, variables),
    railwayQuery(token, DEPLOYMENTS_QUERY, variables),
    railwayQuery(token, VOLUME_INSTANCES_QUERY, { environmentId }),
    railwayQuery(token, COMPLIANCE_QUERY, { projectId: target.project_id }),
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

  // ---------- BACKUP EVIDENCE (volume instance, schedules, backup list) ----------
  const backupErrors = [];
  let volumeNodes = [];
  if (volumeResult.status === 'fulfilled') {
    if (volumeResult.value.status >= 400) backupErrors.push(`volumes HTTP ${volumeResult.value.status}`);
    if (volumeResult.value.body?.errors?.length) backupErrors.push(`volumes: ${volumeResult.value.body.errors[0].message}`);
    const edges = volumeResult.value.body?.data?.environment?.volumeInstances?.edges;
    if (Array.isArray(edges)) volumeNodes = edges.map((edge) => edge?.node).filter(Boolean);
  } else {
    backupErrors.push(`volumes: ${volumeResult.reason?.message ?? 'request failed'}`);
  }

  // Prefer the asset's own service; databases attached to the environment's other
  // services are still part of the same audited deployment.
  const ownService = volumeNodes.filter((node) => node.serviceId && node.serviceId === serviceId);
  const selectedVolumes = ownService.length > 0 ? ownService : volumeNodes;

  const volumes = await Promise.all(
    selectedVolumes.map(async (node) => {
      const [scheduleResult, listResult] = await Promise.allSettled([
        railwayQuery(token, BACKUP_SCHEDULES_QUERY, { volumeInstanceId: node.id }),
        railwayQuery(token, BACKUP_LIST_QUERY, { volumeInstanceId: node.id }),
      ]);

      let schedules = [];
      if (scheduleResult.status === 'fulfilled') {
        if (scheduleResult.value.body?.errors?.length) {
          backupErrors.push(`schedules ${node.id}: ${scheduleResult.value.body.errors[0].message}`);
        }
        const list = scheduleResult.value.body?.data?.volumeInstanceBackupScheduleList;
        if (Array.isArray(list)) schedules = list;
      } else {
        backupErrors.push(`schedules ${node.id}: ${scheduleResult.reason?.message ?? 'request failed'}`);
      }

      let backups = [];
      if (listResult.status === 'fulfilled') {
        if (listResult.value.body?.errors?.length) {
          backupErrors.push(`backups ${node.id}: ${listResult.value.body.errors[0].message}`);
        }
        const list = listResult.value.body?.data?.volumeInstanceBackupList;
        if (Array.isArray(list)) backups = list;
      } else {
        backupErrors.push(`backups ${node.id}: ${listResult.reason?.message ?? 'request failed'}`);
      }

      return {
        volume_instance_id: node.id,
        service_id: node.serviceId ?? null,
        mount_path: node.mountPath ?? null,
        current_size_mb: node.currentSizeMB ?? null,
        schedules,
        backups,
      };
    }),
  );

  // Secondary corroboration only: this field reports an empty array even when
  // schedules and backups exist, so it never decides the outcome.
  let complianceSignal = null;
  if (complianceResult.status === 'fulfilled') {
    if (complianceResult.value.body?.errors?.length) {
      backupErrors.push(`compliance: ${complianceResult.value.body.errors[0].message}`);
    }
    const serviceBackups = complianceResult.value.body?.data?.projectCompliance?.serviceBackups;
    if (Array.isArray(serviceBackups)) complianceSignal = serviceBackups;
  } else {
    backupErrors.push(`compliance: ${complianceResult.reason?.message ?? 'request failed'}`);
  }

  const backups = {
    volumes,
    compliance_signal: complianceSignal,
    selection: {
      service_id: serviceId,
      environment_id: environmentId,
      mode: ownService.length > 0 ? 'service' : volumes.length > 0 ? 'environment' : 'none',
    },
    errors: backupErrors,
  };

  return {
    variables: envMap,
    deployments,
    backups,
    errors,
    discovered,
    environment_id: environmentId,
    service_id: serviceId,
  };
}