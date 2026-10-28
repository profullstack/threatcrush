import { isIP } from "node:net";

/**
 * Connection fields on a server row. `threatcrush connect` hands hostname and
 * ssh_username to the operator's local `ssh`, so a value that starts with "-"
 * (say ssh_username "-oProxyCommand=…") would run a command on the laptop of
 * whoever connects. The CLI refuses these too; this keeps them out of the DB.
 */

const USERNAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/;
const HOSTNAME = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*\.?$/;

export function isSafeSshUsername(value: string): boolean {
  return USERNAME.test(value);
}

export function isSafeHostname(value: string): boolean {
  return HOSTNAME.test(value) || isIP(value) !== 0;
}

/** Why a set of server connection fields is unacceptable, or null. null and "" clear a field. */
export function serverFieldsError(fields: Record<string, unknown>): string | null {
  const blank = (v: unknown) => v === null || v === undefined || v === "";
  if ("hostname" in fields && !blank(fields.hostname)) {
    if (typeof fields.hostname !== "string" || !isSafeHostname(fields.hostname)) return "hostname must be a DNS name or IP address";
  }
  if ("ip_address" in fields && !blank(fields.ip_address)) {
    if (typeof fields.ip_address !== "string" || isIP(fields.ip_address) === 0) return "ip_address must be an IP address";
  }
  if ("ssh_username" in fields && !blank(fields.ssh_username)) {
    if (typeof fields.ssh_username !== "string" || !isSafeSshUsername(fields.ssh_username)) {
      return "ssh_username may only contain letters, digits, '_', '.' and '-', and cannot start with '-'";
    }
  }
  if ("port" in fields && !blank(fields.port)) {
    const port = fields.port;
    if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) return "port must be 1-65535";
  }
  if ("name" in fields && (typeof fields.name !== "string" || !fields.name.trim() || fields.name.length > 200)) {
    return "name must be a non-empty string";
  }
  return null;
}
