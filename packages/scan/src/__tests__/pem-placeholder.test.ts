import { describe,it,expect } from 'vitest';
import { scanText } from '../text';
describe('private key placeholder evidence',()=>{
  const severity=(body:string,file='.env.example')=>scanText(file,`KEY=-----BEGIN PRIVATE KEY-----\\n${body}\\n-----END PRIVATE KEY-----`).find(f=>f.ruleId==='secret-private-key')?.severity;
  it('reports an exact dummy body as a warning, including escaped PEM values',()=>expect(severity('your-pem-body-here')).toBe('low'));
  it('keeps real key bodies critical in the same example path',()=>expect(severity('MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSk')).toBe('critical'));
  it('does not soften a mix of dummy and actual material',()=>expect(severity('your-pem-body-here\\nMIIEvgIBADAN')).toBe('critical'));
  it('does not soften a header without a matching footer',()=>expect(scanText('.env.example','-----BEGIN PRIVATE KEY-----\nyour-pem-body-here').find(f=>f.ruleId==='secret-private-key')?.severity).toBe('critical'));
});
