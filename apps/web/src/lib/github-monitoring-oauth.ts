import "server-only";
import { NextRequest,NextResponse } from "next/server";
import { getSupabaseAdmin } from "./supabase";
import { hashSecret,isOrgAdmin,orgRoleOf } from "./access";
import { linkIdentity } from "./github-monitoring";

/** Connects a GitHub identity without replacing a CoinPay/email login. */
export async function githubMonitoringCallback(req:NextRequest) {
  const url=new URL(req.url),state=url.searchParams.get("state")||"",code=url.searchParams.get("code");
  const base=(process.env.NEXT_PUBLIC_APP_URL||"https://threatcrush.com").replace(/\/$/,"");
  const redirect=(error?:string)=>{const r=NextResponse.redirect(base+"/account?github="+(error?encodeURIComponent(error):"connected")+"#github-monitoring");r.cookies.set("tc_github_monitor_state","",{path:"/api/auth/callback",maxAge:0});return r;};
  if(!/^tcm_[\w-]{43}$/.test(state)||req.cookies.get("tc_github_monitor_state")?.value!==state)return redirect("Connection expired. Start again from your account.");
  const admin=getSupabaseAdmin();
  const claimed=await admin.from("github_monitoring_oauth_states").delete().eq("state_hash",hashSecret(state)).gt("expires_at",new Date().toISOString()).select("user_id,org_id,verifier").maybeSingle();
  if(claimed.error||!claimed.data||!code)return redirect("Connection expired or GitHub authorization was cancelled.");
  const s=claimed.data;
  if(!isOrgAdmin(await orgRoleOf(admin,{kind:"user",userId:s.user_id,email:null},s.org_id)))return redirect("Organization admin access required.");
  try {
    const res=await fetch("https://github.com/login/oauth/access_token",{method:"POST",headers:{Accept:"application/json","Content-Type":"application/json"},redirect:"error",signal:AbortSignal.timeout(30000),body:JSON.stringify({client_id:process.env.GITHUB_CLIENT_ID,client_secret:process.env.GITHUB_CLIENT_SECRET,code,code_verifier:s.verifier,redirect_uri:base+"/api/auth/callback"})});
    const token=await res.json();
    if(!res.ok||typeof token.access_token!=="string")throw new Error("GitHub did not authorize the connection. Please retry.");
    await linkIdentity(admin,s.org_id,s.user_id,token.access_token);
    return redirect();
  } catch {return redirect("Could not connect GitHub. Retry, or use the GitHub token option.");}
}
