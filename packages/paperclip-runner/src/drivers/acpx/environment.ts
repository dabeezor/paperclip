import type { QualifiedAcpxAgent } from "./qualified-profiles.js";

/**
 * Build the complete environment visible to the ACPX sidecar. Agent-specific
 * homes and bridge secrets are injected just in time by AcpxRuntimeHost and
 * never inherited from the Paperclip server process.
 */
export function createSanitizedAcpxEnvironment(
  environment: NodeJS.ProcessEnv | undefined,
  agent: QualifiedAcpxAgent,
): NodeJS.ProcessEnv {
  const source = environment ?? process.env;
  const result: NodeJS.ProcessEnv = {};
  const credentialNames =
    agent === "pi"
      ? ["OPENROUTER_API_KEY"]
      : agent === "claude"
        ? ["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"]
        : [
            "OPENAI_API_KEY",
            "CODEX_API_KEY",
            "PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET",
          ];
  const allowed = new Set([
    "PATH",
    "LANG",
    "LANGUAGE",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "all_proxy",
    "RUST_BACKTRACE",
    "PAPERCLIP_NATIVE_MCP_NAME",
    "PAPERCLIP_NATIVE_MCP_URL",
    ...credentialNames,
  ]);
  let retainedBytes = 0;
  for (const [key, value] of Object.entries(source)) {
    if (typeof value !== "string") continue;
    if (!allowed.has(key) && !/^LC_[A-Z0-9_]{1,32}$/.test(key)) continue;
    if (key.includes("\0") || value.includes("\0")) {
      throw new Error("ACPX environment contains a null byte");
    }
    const entryBytes = Buffer.byteLength(key) + Buffer.byteLength(value);
    if (entryBytes > 64 * 1024 || retainedBytes + entryBytes > 256 * 1024) {
      throw new Error("ACPX environment exceeds its bounded launch size");
    }
    retainedBytes += entryBytes;
    result[key] = value;
  }
  return result;
}
