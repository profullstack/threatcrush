// Shapes of the generated OWASP CRS table (rules.generated.ts). Every string a
// rule matches against is a byte string: one char per byte, codes 0-255, the
// way ModSecurity sees a request.

export type CrsSeverity = 'CRITICAL' | 'ERROR' | 'WARNING' | 'NOTICE';

/** The request parts an access log records, named as CRS names them. */
export type CrsTarget =
  | 'ARGS'
  | 'ARGS_NAMES'
  | 'QUERY_STRING'
  | 'REQUEST_FILENAME'
  | 'REQUEST_URI_RAW'
  | 'REQUEST_LINE'
  | 'REQUEST_HEADERS:User-Agent'
  | 'REQUEST_HEADERS:Referer';

export type CrsTransform =
  | 'lowercase'
  | 'urlDecodeUni'
  | 'htmlEntityDecode'
  | 'jsDecode'
  | 'cssDecode'
  | 'removeNulls'
  | 'removeWhitespace'
  | 'compressWhitespace'
  | 'replaceComments'
  | 'removeCommentsChar'
  | 'cmdLine'
  | 'normalizePath'
  | 'normalizePathWin'
  | 'utf8toUnicode'
  | 'base64Decode';

export type CrsOperator =
  | { type: 'rx'; source: string; flags: string; negated: boolean }
  | { type: 'pm'; phrases: string[]; negated: boolean }
  | { type: 'contains' | 'streq' | 'beginsWith' | 'endsWith' | 'within'; arg: string; negated: boolean };

/** A chained SecRule, evaluated against what the rule before it matched. */
export interface CrsChainLink {
  target: 'MATCHED_VARS' | 'MATCHED_VAR';
  transforms: CrsTransform[];
  op: CrsOperator;
}

export interface CrsRule {
  id: number;
  msg: string;
  severity: CrsSeverity;
  /** The rule's `attack-*` tags. */
  tags: string[];
  targets: CrsTarget[];
  transforms: CrsTransform[];
  multiMatch?: boolean;
  op: CrsOperator;
  chain?: CrsChainLink[];
}
