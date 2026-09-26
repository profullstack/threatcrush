/**
 * "Continue with GitHub" only works once the GitHub provider is enabled in
 * Supabase Auth; until then Supabase answers `400 Unsupported provider`. Set
 * NEXT_PUBLIC_GITHUB_OAUTH_ENABLED=true after enabling it. Client bundles
 * inline the value at build time, so changing it needs a rebuild.
 */
export function githubOAuthEnabled(): boolean {
  return process.env.NEXT_PUBLIC_GITHUB_OAUTH_ENABLED === "true";
}
