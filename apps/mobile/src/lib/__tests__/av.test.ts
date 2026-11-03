import { describe, expect, it } from 'vitest';
import { base64ToBytes, nameFromUri, scanBase64 } from '../av';

const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

describe('mobile av helpers', () => {
  it('decodes base64 exactly like Buffer, for every padding length', () => {
    for (const s of ['', 'a', 'ab', 'abc', 'abcd', EICAR, 'ÿ\u0000binary']) {
      const b64 = Buffer.from(s, 'latin1').toString('base64');
      expect(Buffer.from(base64ToBytes(b64)).toString('latin1')).toBe(s);
    }
  });

  it('names Android SAF documents by their last path segment', () => {
    expect(nameFromUri('content://com.android.externalstorage.documents/tree/primary%3ADownload/document/primary%3ADownload%2Fsetup.apk')).toBe('setup.apk');
    expect(nameFromUri('file:///data/x/eicar.com')).toBe('eicar.com');
  });

  it('scans base64 content with the shared engine', async () => {
    const r = await scanBase64('eicar.com', Buffer.from(EICAR, 'latin1').toString('base64'));
    expect(r.verdict).toBe('malicious');
  });
});
