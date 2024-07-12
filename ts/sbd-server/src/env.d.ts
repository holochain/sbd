/**
 * Cloudflare worker environment objects.
 */
interface EnvExplicit {
  SBD_COORDINATION: KVNamespace;
  SIGNAL: DurableObjectNamespace;
  RATE_LIMIT: DurableObjectNamespace;
}

/**
 * Cloudflare worker environment variables.
 */
interface EnvVars {
  [index: string]: string;
}

/**
 * Combined Cloudflare Env type.
 */
type Env = EnvExplicit & EnvVars;
