import { describe,it,expect } from 'vitest';
import { scanText } from '../text';
describe('private key placeholder evidence',()=>{
  const REAL='MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSk';
  const severity=(body:string,file='.env.example')=>scanText(file,`KEY=-----BEGIN PRIVATE KEY-----\\n${body}\\n-----END PRIVATE KEY-----`).find(f=>f.ruleId==='secret-private-key')?.severity;
  // A dummy body is no key body at all, so the banner around it is skipped (see hasPemBody).
  it('skips an exact dummy body, including escaped PEM values',()=>expect(severity('your-pem-body-here')).toBeUndefined());
  it('keeps real key bodies critical in the same example path',()=>expect(severity(REAL)).toBe('critical'));
  it('does not soften a mix of dummy and actual material',()=>expect(severity(`your-pem-body-here\\n${REAL}`)).toBe('critical'));
  it('does not soften a header without a matching footer',()=>expect(scanText('.env.example',`-----BEGIN PRIVATE KEY-----\n${REAL}`).find(f=>f.ruleId==='secret-private-key')?.severity).toBe('critical'));
});
