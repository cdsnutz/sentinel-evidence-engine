import { createClientFromRequest } from 'npm:@base44/sdk@0.8.54';
import { runGithubProbes, runRailwayProbes, loadGithubTargets, loadRailwayTargets } from '../../shared/engine.ts';

export default async function (req) {
  try {
    const base44 = createClientFromRequest(req);
    const user = await base44.auth.me().catch(() => null);
    if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });
    if (user.role !== 'admin') return Response.json({ error: 'Forbidden' }, { status: 403 });

    const payload = await req.json().catch(() => ({}));
    const providers = Array.isArray(payload.providers) && payload.providers.length
      ? payload.providers
      : ['github', 'railway'];
    const mode = payload.mode === 'fixture' ? 'fixture' : 'live';

    const githubTargets = Array.isArray(payload?.targets?.github)
      ? payload.targets.github
      : providers.includes('github')
        ? await loadGithubTargets(base44)
        : [];

    const railwayTargets = Array.isArray(payload?.targets?.railway)
      ? payload.targets.railway
      : providers.includes('railway')
        ? await loadRailwayTargets(base44)
        : [];

    const runs = [];
    for (const target of githubTargets) {
      runs.push(await runGithubProbes(base44, target, { mode }));
    }
    for (const target of railwayTargets) {
      runs.push(await runRailwayProbes(base44, target, { mode }));
    }

    return Response.json({
      ran_at: new Date().toISOString(),
      mode,
      providers,
      targets_evaluated: runs.length,
      runs,
      note: runs.length === 0
        ? 'No targets configured. Add MonitoredAsset records (provider github or railway) or pass targets in the payload.'
        : undefined,
    });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}