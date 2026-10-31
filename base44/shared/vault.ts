import { secrets } from 'base44:runtime';

// The single seam where credentials are resolved. Today this is the platform
// secret store; pointing it at a separate "Sovereign Vault" table later only
// changes this file.
const SECRET_NAMES = {
  github: 'GITHUB_TOKEN',
  railway: 'RAILWAY_TOKEN',
};

function readSecret(name) {
  try {
    const fromRuntime = secrets?.get ? secrets.get(name) : null;
    if (fromRuntime) return String(fromRuntime);
  } catch (_) {
    // unset secret throws in the runtime — fall through
  }
  try {
    return Deno.env.get(name) ?? null;
  } catch (_) {
    return null;
  }
}

export function resolveToken(provider, callerToken) {
  if (typeof callerToken === 'string' && callerToken.trim()) {
    return { token: callerToken.trim(), source: 'caller' };
  }
  const name = SECRET_NAMES[provider];
  const value = name ? readSecret(name) : null;
  if (value && value.trim()) return { token: value.trim(), source: 'platform_secret' };
  return { token: null, source: 'none' };
}

export function secretNames() {
  return SECRET_NAMES;
}