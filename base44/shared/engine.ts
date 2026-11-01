import {
  probeGitHubBranchProtection,
  probeGitHubRequiredSignatures,
  probeGitHubAdminAccessReview,
} from './probes/github.ts';
import {
  probeRailwayBackups,
  probeRailwayEnvLeakage,
  probeRailwayDeploymentTraceability,
  fetchRailwaySnapshot,
} from './probes/railway.ts';
import { resolveToken } from './vault.ts';
import { persistResults } from './evidence.ts';

function readRows(response) {
  return Array.isArray(response) ? response : (response?.items ?? []);
}

export async function loadSecurityTags(base44) {
  const rows = readRows(await base44.asServiceRole.entities.SecurityRoster.list({ limit: 500 }));
  const map = {};
  for (const row of rows) {
    if (!row?.github_login) continue;
    map[String(row.github_login).toLowerCase()] = Array.isArray(row.tags) ? row.tags : [];
  }
  return map;
}

export async function runGithubProbes(base44, target, options = {}) {
  const mode = options.mode ?? 'live';
  const { token, source } = resolveToken('github', target.token);
  const securityTags = await loadSecurityTags(base44);
  const started = Date.now();

  const results = await Promise.all([
    probeGitHubBranchProtection(token, target.owner, target.repo, target.branch || 'main'),
    probeGitHubRequiredSignatures(token, target.owner, target.repo, target.branch || 'main'),
    probeGitHubAdminAccessReview(token, target.owner, target.repo, securityTags),
  ]);

  const persisted = await persistResults(base44, results, {
    mode,
    token_source: source,
    duration_ms: Date.now() - started,
  });

  return {
    provider: 'github',
    target: `${target.owner}/${target.repo}@${target.branch || 'main'}`,
    token_source: source,
    results,
    persisted,
  };
}

export async function runRailwayProbes(base44, target, options = {}) {
  const mode = options.mode ?? 'live';
  const { token, source } = resolveToken('railway', target.token);
  const started = Date.now();
  const label = target.label || target.project_id || 'railway/service';

  const snapshot = token
    ? await fetchRailwaySnapshot(token, target)
    : { variables: null, deployments: null, errors: ['RAILWAY_TOKEN is not set'] };

  const results = [
    probeRailwayBackups(snapshot.backups ?? null, label, { service_id: target.service_id ?? null }),
    probeRailwayEnvLeakage(snapshot.variables, label),
    probeRailwayDeploymentTraceability(snapshot.deployments, label),
  ].map((result) => (snapshot.errors?.length
    ? {
        ...result,
        reason: `${result.reason} · ${snapshot.errors[0]}`,
        evidence: { ...result.evidence, connection_errors: snapshot.errors },
      }
    : result));

  const persisted = await persistResults(base44, results, {
    mode,
    token_source: source,
    duration_ms: Date.now() - started,
  });

  return { provider: 'railway', target: label, token_source: source, errors: snapshot.errors, results, persisted };
}

export async function loadGithubTargets(base44) {
  const rows = readRows(await base44.asServiceRole.entities.MonitoredAsset.list({ limit: 200 }));
  return rows
    .filter((row) => row.provider === 'github' && row.active !== false && row.owner && row.repo)
    .map((row) => ({ owner: row.owner, repo: row.repo, branch: row.branch || 'main' }));
}

export async function loadRailwayTargets(base44) {
  const rows = readRows(await base44.asServiceRole.entities.MonitoredAsset.list({ limit: 200 }));
  return rows
    .filter((row) => row.provider === 'railway' && row.active !== false && row.project_id)
    .map((row) => ({
      label: row.label || row.project_id,
      project_id: row.project_id,
      environment_id: row.environment_id ?? null,
      service_id: row.service_id ?? null,
      settings: row.settings ?? null,
    }));
}

export { readRows };