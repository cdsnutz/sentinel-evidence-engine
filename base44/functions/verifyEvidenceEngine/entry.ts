import { createClientFromRequest } from 'npm:@base44/sdk@0.8.54';
import { probeGitHubBranchProtection, probeGitHubRequiredSignatures, probeGitHubAdminAccessReview } from '../../shared/probes/github.ts';
import { probeRailwayBackups, probeRailwayEnvLeakage, probeRailwayDeploymentTraceability } from '../../shared/probes/railway.ts';
import { loadSecurityTags, readRows, loadRailwayTargets, loadGithubTargets, runRailwayProbes, runGithubProbes } from '../../shared/engine.ts';
import { resolveToken } from '../../shared/vault.ts';
import { persistResults } from '../../shared/evidence.ts';

// Public repositories with a protected default branch. The probe reads the real
// GitHub API; whichever candidate answers first proves the PASS path.
const PROTECTED_CANDIDATES = [
  { owner: 'facebook', repo: 'react', branch: 'main' },
  { owner: 'vercel', repo: 'next.js', branch: 'canary' },
  { owner: 'nodejs', repo: 'node', branch: 'main' },
  { owner: 'microsoft', repo: 'vscode', branch: 'main' },
  { owner: 'kubernetes', repo: 'kubernetes', branch: 'master' },
];

const UNPROTECTED_CANDIDATE = { owner: 'octocat', repo: 'Hello-World', branch: 'master' };

export default async function (req) {
  try {
    const base44 = createClientFromRequest(req);
    // A user token, when present, must be an admin. Workflow and platform test
    // invocations carry no user token; they may run the harness.
    const user = await base44.auth.me().catch(() => null);
    if (user && user.role !== 'admin') {
      return Response.json({ error: 'Forbidden' }, { status: 403 });
    }

    const notes = [];

    // ---------- 1. SUCCESS LOG (live GitHub read) ----------
    const gh = resolveToken('github', null);
    const attempts = [];
    let provenSuccess = null;

    for (const candidate of PROTECTED_CANDIDATES) {
      const result = await probeGitHubBranchProtection(gh.token, candidate.owner, candidate.repo, candidate.branch);
      attempts.push({ target: result.target, status: result.status, reason: result.reason, http_status: result.http_status });
      if (result.status === 'PASS') {
        provenSuccess = result;
        break;
      }
    }

    let githubSecondary = [];
    if (provenSuccess) {
      const securityTags = await loadSecurityTags(base44);
      const [owner, rest] = provenSuccess.target.split('/');
      const repo = (rest || '').split('@')[0];
      const branch = (provenSuccess.target.split('@')[1] || 'main');
      const secondary = await Promise.all([
        probeGitHubRequiredSignatures(gh.token, owner, repo, branch),
        probeGitHubAdminAccessReview(gh.token, owner, repo, securityTags),
      ]);
      githubSecondary = secondary.map((r) => ({ probe_id: r.probe_id, status: r.status, reason: r.reason }));
      await persistResults(base44, [provenSuccess, ...secondary], {
        mode: 'live',
        token_source: gh.source,
        duration_ms: 0,
      });
    }

    if (gh.source === 'none') {
      notes.push('No GITHUB_TOKEN secret set: live GitHub reads are unauthenticated (branch protection is public; commit signing and collaborator review need a token).');
    }

    // ---------- 2. FAILURE LOG (live FAIL + pure-function FAILs) ----------
    const unprotected = await probeGitHubBranchProtection(
      gh.token,
      UNPROTECTED_CANDIDATE.owner,
      UNPROTECTED_CANDIDATE.repo,
      UNPROTECTED_CANDIDATE.branch,
    );

    const railwayFixture = [
      probeRailwayBackups({ backups: { disabled: true } }, 'fixture/railway-service'),
      probeRailwayEnvLeakage({ DATABASE_PASSWORD: '1234', NODE_ENV: 'production' }, 'fixture/railway-service'),
      probeRailwayDeploymentTraceability(
        [{ id: 'dep_manual_1', status: 'SUCCESS', meta: { source: 'manual' } }],
        'fixture/railway-service',
      ),
    ];

    await persistResults(base44, [unprotected], { mode: 'live', token_source: gh.source, duration_ms: 0 });
    await persistResults(base44, railwayFixture, { mode: 'fixture', token_source: 'none', duration_ms: 0 });

    const rw = resolveToken('railway', null);
    if (rw.source === 'none') {
      notes.push('No RAILWAY_TOKEN secret set: the Railway probes were proven against a fixture payload, not a live Railway workspace. Add the token and a MonitoredAsset to turn those rows live.');
    }

    const failureChecks = [
      {
        probe_id: 'github_branch_protection',
        mode: 'live',
        target: unprotected.target,
        expected: 'FAIL',
        status: unprotected.status,
        reason: unprotected.reason,
      },
      ...railwayFixture.map((result) => ({
        probe_id: result.probe_id,
        mode: 'fixture',
        target: result.target,
        expected: 'FAIL',
        status: result.status,
        reason: result.reason,
      })),
    ];
    const failureProven = failureChecks.every((check) => check.status === 'FAIL');

    // ---------- CONFIGURED MONITORED ASSETS (real targets) ----------
    const configuredAssets = [];
    const railwayTargets = await loadRailwayTargets(base44);
    for (const target of railwayTargets) {
      const run = await runRailwayProbes(base44, target, { mode: 'live' });
      configuredAssets.push({
        provider: 'railway',
        target: run.target,
        token_source: run.token_source,
        connection_errors: run.errors,
        results: run.results.map((result) => ({
          probe_id: result.probe_id,
          status: result.status,
          reason: result.reason,
        })),
      });
      if (run.errors?.some((err) => /not authorized|401|unauthor/i.test(err))) {
        notes.push(`Railway credential rejected for ${run.target}: ${run.errors[0]}`);
      }
    }
    const githubTargets = await loadGithubTargets(base44);
    for (const target of githubTargets) {
      const run = await runGithubProbes(base44, target, { mode: 'live' });
      configuredAssets.push({
        provider: 'github',
        target: run.target,
        token_source: run.token_source,
        connection_errors: [],
        results: run.results.map((result) => ({
          probe_id: result.probe_id,
          status: result.status,
          reason: result.reason,
        })),
      });
    }

    // ---------- 3. DATABASE STATE ----------
    const controlRows = readRows(
      await base44.asServiceRole.entities.ControlMap.list({ sort: 'control_id', limit: 200 }),
    );
    const dump = controlRows.map((row) => ({
      control_id: row.control_id,
      probe_id: row.probe_id,
      target: row.target,
      requirement: row.requirement,
      status: row.status,
      evidence_mode: row.evidence_mode,
      last_run_at: row.last_run_at,
    }));
    const mappedControls = new Set(dump.filter((row) => String(row.control_id).startsWith('SOC2-')).map((row) => row.control_id));
    const databaseProven = dump.length >= 6 && mappedControls.size >= 5;

    // ---------- LOGIC SUITE (pure functions, no network) ----------
    const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString();
    const logicSuite = [];
    const check = (label, result, expected) => {
      logicSuite.push({ case: label, expected, actual: result.status, matched: result.status === expected });
    };
    check(
      'backups · disabled -> FAIL',
      probeRailwayBackups({ backups: { disabled: true } }, 'logic'),
      'FAIL',
    );
    check(
      'backups · 30 days stale -> FAIL',
      probeRailwayBackups({ backups: { enabled: true, lastBackupAt: thirtyDaysAgo } }, 'logic'),
      'FAIL',
    );
    check(
      'backups · fresh -> PASS',
      probeRailwayBackups({ backups: { enabled: true, lastBackupAt: new Date().toISOString() } }, 'logic'),
      'PASS',
    );
    check(
      'env leakage · PASSWORD=1234 -> FAIL',
      probeRailwayEnvLeakage({ DB_PASSWORD: '1234' }, 'logic'),
      'FAIL',
    );
    check(
      'env leakage · strong secret -> PASS',
      probeRailwayEnvLeakage({ DB_PASSWORD: 'Xq7#vLm2-Pz9!Rt4wB' }, 'logic'),
      'PASS',
    );
    check(
      'traceability · manual deploy -> FAIL',
      probeRailwayDeploymentTraceability([{ id: 'dep_manual_2', meta: { source: 'manual' } }], 'logic'),
      'FAIL',
    );
    check(
      'traceability · commit-linked deploy -> PASS',
      probeRailwayDeploymentTraceability([{ id: 'dep_git_1', meta: { commitHash: '9f2c1ab' } }], 'logic'),
      'PASS',
    );

    return Response.json({
      generated_at: new Date().toISOString(),
      verification_complete: Boolean(provenSuccess) && failureProven && databaseProven,
      artifacts: {
        success_log: {
          proven: Boolean(provenSuccess),
          mode: 'live',
          token_source: gh.source,
          probe_id: provenSuccess?.probe_id ?? null,
          control_id: provenSuccess?.control_id ?? null,
          target: provenSuccess?.target ?? null,
          reason: provenSuccess?.reason ?? null,
          evidence: provenSuccess?.evidence ?? null,
          attempts,
          secondary_probes: githubSecondary,
        },
        failure_log: {
          proven: failureProven,
          mode: 'mixed',
          checks: failureChecks,
        },
        database_state: {
          proven: databaseProven,
          rows: dump.length,
          controls_mapped: Array.from(mappedControls).sort(),
          control_map: dump,
        },
      },
      logic_suite: logicSuite,
      notes,
      configured_assets: configuredAssets,
    });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}