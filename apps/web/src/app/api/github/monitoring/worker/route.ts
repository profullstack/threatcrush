import { timingSafeEqual,createHash } from "node:crypto";
import { NextRequest,NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { discoverOwner,runMonitoringJob,type MonitoringOwner } from "@/lib/github-monitoring";
export const runtime="nodejs";
export const maxDuration=900;
export async function POST(req:NextRequest) {
  const expected=process.env.GITHUB_MONITOR_WORKER_KEY,token=req.headers.get("authorization")?.replace(/^Bearer\s+/i,"")||"";
  const hash=(s:string)=>createHash("sha256").update(s).digest();
  if(!expected||!timingSafeEqual(hash(expected),hash(token)))return NextResponse.json({error:"Not authorized"},{status:401});
  const admin=getSupabaseAdmin();
  try {
    const owners=await admin.from("github_monitoring_owners").select("*").eq("enabled",true).or(`last_discovery_at.is.null,last_discovery_at.lt.${new Date(Date.now()-6*3600000).toISOString()}`).order("last_discovery_at",{ascending:true,nullsFirst:true}).limit(1);
    if(owners.error)throw new Error("Discovery queue unavailable");
    for(const owner of owners.data??[])try {await discoverOwner(admin,owner as MonitoringOwner);}catch {await admin.from("github_monitoring_owners").update({error:"GitHub discovery failed; check app access and retry sync",last_discovery_at:new Date().toISOString()}).eq("id",owner.id);}
    return NextResponse.json(await runMonitoringJob(admin),{headers:{"Cache-Control":"no-store"}});
  }catch{return NextResponse.json({error:"Monitoring worker failed; queued work is retained"},{status:503});}
}
