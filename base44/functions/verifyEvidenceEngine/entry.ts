import { createClientFromRequest } from 'npm:@base44/sdk@0.8.54';
import { evaluateBranchProtection } from '../../shared/probes/github.ts';
import { probeRailwayBackups, probeRailwayEnvLeakage, probeRailwayDeploymentTraceability } from '../../shared/probes/railway.ts';
import { readRows, loadRailwayTargets, loadGithubTargets, runRailwayProbes, runGithubProbes } from '../../shared/engine.ts';
import { resolveToken } from '../../shared/vault.ts';
import { persistResults } from '../../shared/evidence.ts';

// The PASS and FAIL paths are proven against in-memory provider payloads, never
// against a repository the owner does not own. These targets are not assets and
// are never allowed to become ControlMap rows.
const PROTECTED_BRANCH_FIXTURE = {
  target: 'fixture/protected-branch',
  payload: { name: 'main', protected: true, commit: { sha: 'fixture-sha-protected' } },
};

const UNPROTECTED_BRANCH_FIXTURE = {
  target: 'fixture/unprotected-branch',
  payload: { name: 'main', protected: false, commit: { sha: 'fixture-sha-unprotected' } },
};

export default async function (req) {
  try {
    const base44 = createClientFromRequest(req);
    // A user token, when present, must be an admin. Workflow and platform test
    // invocations carry no user token; they may run the harness.
    const user = await base44.auth.me().catch(() => null);
    if (user && user.role !== 'admin') {
      return Response.json({ error: 'Forbidden' }, { status: 403 });
    }

    const generatedAt = new Date().toISOString();
    const notes = [];

    // ---------- PURE FIXTURES (no network, no control state) ----------
    const protectedFixture = evaluateBranchProtection(
      PROTECTED_BRANCH_FIXTURE.payload,
      PROTECTED_BRANCH_FIXTURE.target,
      { branch: 'main' },
    );
    const unprotectedFixture = evaluateBranchProtection(
      UNPROTECTED_BRANCH_FIXTURE.payload,
      UNPROTECTED_BRANCH_FIXTURE.target,
      { branch: 'main' },
    );

    // A volume instance whose schedules exist but which holds no backup at all.
    const backupVolumeSnapshot = (schedules, backups) => ({
      volumes: [
        {
          volume_instance_id: 'fixture-volume-instance',
          service_id: 'fixture-service',
          mount_path: '/var/lib/postgresql/data',
          schedules,
          backups,
        },
      ],
      compliance_signal: [],
      selection: { service_id: 'fixture-service', mode: 'service' },
    });

    const railwayFixture = [
      probeRailwayBackups(backupVolumeSnapshot([], []), 'fixture/railway-service'),
      probeRailwayEnvLeakage({ DATABASE_PASSWORD: '1234', NODE_ENV: 'production' }, 'fixture/railway-service'),
      probeRailwayDeploymentTraceability(
        [{ id: 'dep_manual_1', status: 'SUCCESS', meta: { source: 'manual' } }],
        'fixture/railway-service',
      ),
    ];

    const successProven = protectedFixture.status === 'PASS';
    const failureChecks = [unprotectedFixture, ...railwayFixture].map((result) => ({
      probe_id: result.probe_id,
      source: 'fixture',
      mode: 'fixture',
      target: result.target,
      expected: 'FAIL',
      status: result.status,
      reason: result.reason,
    }));
    const failureProven = failureChecks.every((check) => check.status === 'FAIL');

    // ---------- CONFIGURED MONITORED ASSETS (the only real targets) ----------
    const githubTargets = await loadGithubTargets(base44);
    const railwayTargets = await loadRailwayTargets(base44);
    const configuredCount = githubTargets.length + railwayTargets.length;

    // Every target the truth table is allowed to carry.
    const assetKeys = new Set();
    for (const target of githubTargets) {
      assetKeys.add(`${target.owner}/${target.repo}@${target.branch || 'main'}`);
      assetKeys.add(`${target.owner}/${target.repo}`);
    }
    for (const target of railwayTargets) {
      assetKeys.add(target.label || target.project_id);
    }

    if (configuredCount === 0) {
      return Response.json({
        generated_at: generatedAt,
        verification_complete: false,
        target_source: 'none',
        reason: 'no monitored asset configured',
        artifacts: {
          success_log: {
            proven: false,
            source: 'none',
            mode: 'none',
            reason: 'no monitored asset configured',
          },
          failure_log: {
            proven: false,
            source: 'none',
            mode: 'none',
            reason: 'no monitored asset configured',
            checks: [],
          },
          database_state: {
            proven: false,
            rows: 0,
            controls_mapped: [],
            control_map: [],
          },
          evaluated_assets: [],
        },
        logic_suite: [],
        notes: [
          'No active MonitoredAsset rows: nothing was probed and no ProbeRun or ControlMap rows were written.',
        ],
      });
    }

    // ---------- LIVE EVALUATION OF THE CONFIGURED ASSETS ----------
    const evaluatedAssets = [];

    for (const target of githubTargets) {
      const run = await runGithubProbes(base44, target, { mode: 'live' });
      evaluatedAssets.push({
        provider: 'github',
        target: run.target,
        token_source: run.token_source,
        connection_errors: run.results
          .filter((result) => result.http_status === 401)
          .map(() => 'GitHub returned HTTP 401'),
        results: run.results.map((result) => ({
          probe_id: result.probe_id,
          target: result.target,
          status: result.status,
          reason: result.reason,
        })),
      });
    }

    for (const target of railwayTargets) {
      const run = await runRailwayProbes(base44, target, { mode: 'live' });
      evaluatedAssets.push({
        provider: 'railway',
        target: run.target,
        token_source: run.token_source,
        connection_errors: run.errors,
        results: run.results.map((result) => ({
          probe_id: result.probe_id,
          target: result.target,
          status: result.status,
          reason: result.reason,
        })),
      });
      if (run.errors?.some((err) => /not authorized|401|unauthor/i.test(err))) {
        notes.push(`Railway credential rejected for ${run.target}: ${run.errors[0]}`);
      }
    }

    const evaluatedCount = evaluatedAssets.filter((asset) => asset.results.length > 0).length;

    const gh = resolveToken('github', null);
    if (gh.source === 'none') {
      notes.push('No GITHUB_TOKEN secret set: GitHub reads are unauthenticated, so commit signing and collaborator review fail closed.');
    }
    const rw = resolveToken('railway', null);
    if (rw.source === 'none') {
      notes.push('No RAILWAY_TOKEN secret set: Railway assets cannot be read and their controls fail closed.');
    }

    // Fixture rows are recorded as history only, never as control status.
    await persistResults(base44, [protectedFixture, unprotectedFixture, ...railwayFixture], {
      mode: 'fixture',
      token_source: 'none',
      duration_ms: 0,
      update_control_map: false,
    });

    // ---------- DATABASE STATE (only rows backed by a configured asset) ----------
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
    const backed = dump.filter((row) => assetKeys.has(row.target));
    const unbacked = dump.filter((row) => !assetKeys.has(row.target));
    const mappedControls = new Set(backed.map((row) => row.control_id));
    const assetsRepresented = evaluatedAssets.filter((asset) =>
      asset.results.some((result) => backed.some((row) => row.target === result.target)),
    ).length;
    const databaseProven =
      backed.length > 0 && assetsRepresented === evaluatedCount && unbacked.length === 0;

    if (unbacked.length > 0) {
      notes.push(`${unbacked.length} ControlMap row(s) reference targets that are not configured assets and are excluded from the truth table.`);
    }

    // ---------- LOGIC SUITE (pure functions, no network) ----------
    const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString();
    const logicSuite = [];
    const check = (label, result, expected) => {
      logicSuite.push({ case: label, expected, actual: result.status, matched: result.status === expected });
    };
    check('protected branch fixture -> PASS', protectedFixture, 'PASS');
    check('unprotected branch fixture -> FAIL', unprotectedFixture, 'FAIL');
    check(
      'backups · no schedule -> FAIL',
      probeRailwayBackups(backupVolumeSnapshot([], []), 'logic'),
      'FAIL',
    );
    check(
      'backups · no backup inside the daily window -> FAIL',
      probeRailwayBackups(
        backupVolumeSnapshot(
          [{ name: 'Daily', kind: 'DAILY', cron: '5 0 * * *' }],
          [{ name: 'stale-backup', createdAt: thirtyDaysAgo }],
        ),
        'logic',
      ),
      'FAIL',
    );
    check(
      'backups · fresh daily backup -> PASS',
      probeRailwayBackups(
        backupVolumeSnapshot(
          [{ name: 'Daily', kind: 'DAILY', cron: '5 0 * * *' }],
          [{ name: 'fresh-backup', createdAt: new Date().toISOString() }],
        ),
        'logic',
      ),
      'PASS',
    );
    check(
      'backups · weekly-only, 3 days old -> PASS',
      probeRailwayBackups(
        backupVolumeSnapshot(
          [{ name: 'Weekly', kind: 'WEEKLY', cron: '33 10 * * 6' }],
          [{ name: 'weekly-backup', createdAt: new Date(Date.now() - 3 * 86400000).toISOString() }],
        ),
        'logic',
      ),
      'PASS',
    );
    check(
      'backups · monthly-only, 20 days old -> PASS',
      probeRailwayBackups(
        backupVolumeSnapshot(
          [{ name: 'Monthly', kind: 'MONTHLY', cron: '58 10 1 * *' }],
          [{ name: 'monthly-backup', createdAt: new Date(Date.now() - 20 * 86400000).toISOString() }],
        ),
        'logic',
      ),
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

    const verificationComplete =
      evaluatedCount > 0 && successProven && failureProven && databaseProven;

    return Response.json({
      generated_at: generatedAt,
      verification_complete: verificationComplete,
      target_source: evaluatedCount > 0 ? 'asset' : 'fixture',
      artifacts: {
        success_log: {
          proven: successProven,
          source: 'fixture',
          mode: 'fixture',
          probe_id: protectedFixture.probe_id,
          control_id: protectedFixture.control_id,
          target: protectedFixture.target,
          status: protectedFixture.status,
          reason: protectedFixture.reason,
          evidence: protectedFixture.evidence,
        },
        failure_log: {
          proven: failureProven,
          source: 'fixture',
          mode: 'fixture',
          checks: failureChecks,
        },
        database_state: {
          proven: databaseProven,
          rows: backed.length,
          assets_represented: assetsRepresented,
          controls_mapped: Array.from(mappedControls).sort(),
          control_map: backed,
          unbacked_rows: unbacked.map((row) => ({
            control_id: row.control_id,
            probe_id: row.probe_id,
            target: row.target,
            status: row.status,
          })),
        },
        evaluated_assets: evaluatedAssets,
      },
      logic_suite: logicSuite,
      notes,
    });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}