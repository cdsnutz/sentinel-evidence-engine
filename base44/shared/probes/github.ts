import { buildResult } from './registry.ts';

const GITHUB_API = 'https://api.github.com';
const TIMEOUT_MS = 12000;

function ghHeaders(token) {
  const headers = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'sovereign-evidence-engine',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function ghGet(token, path) {
  const response = await fetch(`${GITHUB_API}${path}`, {
    headers: ghHeaders(token),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  let body = null;
  try {
    body = await response.json();
  } catch (_) {
    body = null;
  }
  return { status: response.status, ok: response.ok, body };
}

// Pure decision: a branch payload in, a control result out. No network, so the
// same function proves the PASS/FAIL paths against fixtures.
export function evaluateBranchProtection(payload, target, options = {}) {
  const isProtected = payload?.protected === true;
  return buildResult(
    'github_branch_protection',
    target,
    isProtected ? 'PASS' : 'FAIL',
    isProtected ? 'branch reports protected=true' : 'branch reports protected=false',
    {
      branch: payload?.name ?? options.branch ?? null,
      protected: payload?.protected ?? false,
      head_sha: payload?.commit?.sha ?? null,
      auth_fallback: Boolean(options.authFallback),
    },
    typeof options.httpStatus === 'number' ? options.httpStatus : null,
  );
}

// GET /repos/{owner}/{repo}/branches/{branch} -> protected: false means FAIL.
export async function probeGitHubBranchProtection(token, owner, repo, branch = 'main') {
  const target = `${owner}/${repo}@${branch}`;
  try {
    const path = `/repos/${owner}/${repo}/branches/${branch}`;
    let res = await ghGet(token, path);
    // Branch protection is public data: a rejected token must not blind the probe.
    const authFallback = Boolean(token) && res.status === 401;
    if (authFallback) res = await ghGet(null, path);
    if (!res.ok) {
      return buildResult(
        'github_branch_protection',
        target,
        'FAIL',
        `unverifiable: GitHub returned HTTP ${res.status}`,
        { error: res.body?.message ?? null },
        res.status,
      );
    }
    return evaluateBranchProtection(res.body, target, {
      branch,
      authFallback,
      httpStatus: res.status,
    });
  } catch (error) {
    return buildResult(
      'github_branch_protection',
      target,
      'FAIL',
      `probe error: ${error.message}`,
      {},
      null,
    );
  }
}

// Required signed commits live on the branch protection rule, not on repo settings.
export async function probeGitHubRequiredSignatures(token, owner, repo, branch = 'main') {
  const target = `${owner}/${repo}@${branch}`;
  try {
    const res = await ghGet(token, `/repos/${owner}/${repo}/branches/${branch}/protection`);
    if (res.status === 404) {
      return buildResult(
        'github_required_signatures',
        target,
        'FAIL',
        'no branch protection rule exists, so signed commits cannot be enforced',
        { rule_present: false },
        res.status,
      );
    }
    if (!res.ok) {
      return buildResult(
        'github_required_signatures',
        target,
        'FAIL',
        `unverifiable: GitHub returned HTTP ${res.status} (a token with admin access to the repo is required)`,
        { error: res.body?.message ?? null },
        res.status,
      );
    }
    const enabled = res.body?.required_signatures?.enabled === true;
    return buildResult(
      'github_required_signatures',
      target,
      enabled ? 'PASS' : 'FAIL',
      enabled ? 'required_signatures.enabled=true' : 'required_signatures is disabled',
      { rule_present: true, required_signatures: res.body?.required_signatures ?? null },
      res.status,
    );
  } catch (error) {
    return buildResult(
      'github_required_signatures',
      target,
      'FAIL',
      `probe error: ${error.message}`,
      {},
      null,
    );
  }
}

// Admin collaborators with no "Security" tag in internal metadata are flagged for review.
export async function probeGitHubAdminAccessReview(token, owner, repo, securityTags = {}) {
  const target = `${owner}/${repo}`;
  try {
    const res = await ghGet(token, `/repos/${owner}/${repo}/collaborators?affiliation=direct&per_page=100`);
    if (!res.ok) {
      return buildResult(
        'github_admin_access_review',
        target,
        'FAIL',
        `unverifiable: GitHub returned HTTP ${res.status} (collaborator enumeration requires an authenticated token)`,
        { error: res.body?.message ?? null },
        res.status,
      );
    }
    const collaborators = Array.isArray(res.body) ? res.body : [];
    const admins = collaborators
      .filter((entry) => entry?.role_name === 'admin' || entry?.permissions?.admin === true)
      .map((entry) => entry?.login)
      .filter(Boolean);
    const flagged = admins.filter((login) => {
      const tags = securityTags[String(login).toLowerCase()] ?? [];
      return !tags.map((tag) => String(tag).toLowerCase()).includes('security');
    });
    const passed = flagged.length === 0;
    return buildResult(
      'github_admin_access_review',
      target,
      passed ? 'PASS' : 'FAIL',
      passed
        ? `all ${admins.length} admin collaborator(s) carry a Security review tag`
        : `${flagged.length} admin collaborator(s) flagged for review without a Security tag`,
      {
        collaborators: collaborators.length,
        admins,
        flagged_for_review: flagged,
        roster_entries: Object.keys(securityTags).length,
      },
      res.status,
    );
  } catch (error) {
    return buildResult(
      'github_admin_access_review',
      target,
      'FAIL',
      `probe error: ${error.message}`,
      {},
      null,
    );
  }
}