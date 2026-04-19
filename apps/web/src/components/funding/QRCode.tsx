'use client';

import { QRCodeCanvas as QRReact } from 'qrcode.react';

export function QRCodeCanvas({ value, size = 224 }: { value: string; size?: number }) {
  return (
    <div className="inline-block rounded-xl bg-white p-3 ring-1 ring-tc-border">
      <QRReact value={value} size={size} level="M" />
    </div>
  );
}
