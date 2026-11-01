import { NextResponse, type NextRequest } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase';
import { getPrincipal } from '@/lib/access';
import { IncidentError, saveIncidentAiTriage } from '@/lib/incidents/store';

export const runtime = 'nodejs';

type Ctx = { params: Promise<{ id: string; incident_id: string }> };
const MAX_BODY_BYTES = 8 * 1024;

/** Persist an AI response produced through the user-metered Responses API. */
export async function POST(req: NextRequest, { params }: Ctx) {
  const admin = getSupabaseAdmin();
  const principal = await getPrincipal(req, admin);
  if (!principal) return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  if (principal.kind !== 'user') return NextResponse.json({ error: 'Use a signed-in user session to save AI triage' }, { status: 403 });
  const { id: orgId, incident_id: incidentId } = await params;
  const raw = await req.text().catch(() => '');
  if (Buffer.byteLength(raw, 'utf8') > MAX_BODY_BYTES) return NextResponse.json({ error: 'AI triage result is too large' }, { status: 413 });
  let body: unknown;
  try { body = JSON.parse(raw); } catch { return NextResponse.json({ error: 'Body must be JSON' }, { status: 400 }); }
  try {
    return NextResponse.json(await saveIncidentAiTriage(admin, principal, orgId, incidentId, body));
  } catch (error) {
    if (error instanceof IncidentError) return NextResponse.json({ error: error.message }, { status: error.status });
    console.error('[incidents] save AI triage', (error as Error).message);
    return NextResponse.json({ error: 'Could not save AI triage' }, { status: 500 });
  }
}
