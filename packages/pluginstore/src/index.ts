export type PluginConfigFieldType = "string" | "number" | "boolean" | "secret" | "url";
export type PluginConfigScope = "global" | "module";

export interface PluginConfigField {
  key: string;
  label: string;
  type: PluginConfigFieldType;
  scope?: PluginConfigScope;
  required?: boolean;
  default?: string | number | boolean | null;
  placeholder?: string;
  help?: string;
  multiline?: boolean;
}

export interface PluginInstallArtifact {
  npm_package: string | null;
  git_url: string | null;
  tarball_url: string | null;
}

export interface PluginInstallPayload {
  name: string;
  slug: string;
  version: string;
  downloads: number;
  license: string | null;
  min_version: string | null;
  os_support: string[] | null;
  config_schema: PluginConfigField[];
  config_notes: string | null;
  install: PluginInstallArtifact;
}

export interface UserInstalledPlugin {
  plugin_id?: string;
  module_id?: string;
  module_slug?: string;
  version: string;
  status: "active" | "disabled" | "removed" | string;
  installed_at: string;
  updated_at?: string;
}

function asConfigField(value: unknown): PluginConfigField | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  if (typeof raw.key !== "string" || !raw.key.trim()) return null;
  if (typeof raw.label !== "string" || !raw.label.trim()) return null;
  if (!["string", "number", "boolean", "secret", "url"].includes(String(raw.type))) return null;

  return {
    key: raw.key.trim(),
    label: raw.label.trim(),
    type: raw.type as PluginConfigFieldType,
    scope: raw.scope === "global" || raw.scope === "module" ? raw.scope : "module",
    required: raw.required === true,
    default:
      typeof raw.default === "string" ||
      typeof raw.default === "number" ||
      typeof raw.default === "boolean" ||
      raw.default === null
        ? raw.default
        : undefined,
    placeholder: typeof raw.placeholder === "string" ? raw.placeholder : undefined,
    help: typeof raw.help === "string" ? raw.help : undefined,
    multiline: raw.multiline === true,
  };
}

export function normalizeConfigSchema(value: unknown): PluginConfigField[] {
  if (!Array.isArray(value)) return [];
  return value.map(asConfigField).filter((field): field is PluginConfigField => field !== null);
}

export function splitConfigSchema(fields: PluginConfigField[]) {
  return {
    secrets: fields.filter((field) => field.type === "secret"),
    plain: fields.filter((field) => field.type !== "secret"),
    global: fields.filter((field) => field.scope === "global"),
    module: fields.filter((field) => (field.scope ?? "module") === "module"),
  };
}
