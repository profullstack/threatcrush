import { after, NextRequest, NextResponse } from "next/server";
import { createHash } from "node:crypto";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal, hashSecret, isOrgAdmin, newSecret, orgRoleOf } from "@/lib/access";
import { isUuid } from "@/lib/incidents/report";
import { enableOwners, installations, linkIdentity, discoverOwner, monitoringAppAccess, canReadContents, GitHubMonitorError, type GitHubOwner, type MonitoringOwner } from "@/lib/github-monitoring";

export const runtime = "nodejs";
export const maxDuration = 300;
const response = (body: unknown, status=200) => NextResponse.json(body,{status,headers:{"Cache-Control":"no-store"}});

export async function GET(req: NextRequest) {
  const admin=getSupabaseAdmin(), p=await getPrincipal(req,admin);
  if(!p||p.kind!=="user")return response({error:"Not authenticated"},401);
  const member=await admin.from("organization_members").select("org_id,role,organizations(name,slug)").eq("user_id",p.userId);
  if(member.error)return response({error:"Could not load organizations"},500);
  const orgs=(member.data??[]).filter(m=>isOrgAdmin(m.role)).map(m=>({id:m.org_id,...(Array.isArray(m.organizations)?m.organizations[0]:m.organizations)}));
  if(!orgs.length)return response({organizations:[],accounts:[],owners:[],repositories:[],oauth_configured:Boolean(process.env.GITHUB_CLIENT_ID&&process.env.GITHUB_CLIENT_SECRET)});
  const ids=orgs.map(o=>o.id);
  const [links,owners]=await Promise.all([
    admin.from("github_monitoring_links").select("id,org_id,github_user_id,github_login,allowed_owners").in("org_id",ids),
    admin.from("github_monitoring_owners").select("id,org_id,account_id,account_login,installation_id,enabled,silence_examples,silence_warnings,last_discovery_at,repository_count,error,github_installations(repository_selection,status)").in("org_id",ids),
  ]);
  if(links.error||owners.error)return response({error:"Could not load GitHub monitoring"},500);
  const ownerIds=(owners.data??[]).map(o=>o.id);
  const jobs=ownerIds.length?await admin.from("github_monitoring_repositories").select("owner_id,status,truncated,last_counts").in("owner_id",ownerIds).limit(10000):{data:[],error:null};
  if(jobs.error)return response({error:"Could not load scan progress"},500);
  return response({organizations:orgs,accounts:links.data,owners:owners.data,repositories:jobs.data,oauth_configured:Boolean(process.env.GITHUB_CLIENT_ID&&process.env.GITHUB_CLIENT_SECRET)});
}

export async function POST(req: NextRequest) {
  const admin=getSupabaseAdmin(),p=await getPrincipal(req,admin);
  if(!p||p.kind!=="user")return response({error:"Not authenticated"},401);
  const b=await req.json().catch(()=>null);
  if(!b||!isUuid(b.org_id))return response({error:"Select an organization"},400);
  if(!isOrgAdmin(await orgRoleOf(admin,p,b.org_id)))return response({error:"Organization owner/admin access required"},403);
  try {
    if(b.action==="connect") {
      if(typeof b.token==="string") {
        if(b.token.length<20||b.token.length>1000)return response({error:"Invalid GitHub token"},400);
        const identity=await linkIdentity(admin,b.org_id,p.userId,b.token);
        return response({connected:identity.user.login});
      }
      if(!process.env.GITHUB_CLIENT_ID||!process.env.GITHUB_CLIENT_SECRET)return response({error:"GitHub OAuth is not configured; use a GitHub token to verify your account"},503);
      const state="tcm_"+newSecret(),verifier=newSecret();
      const saved=await admin.from("github_monitoring_oauth_states").insert({state_hash:hashSecret(state),user_id:p.userId,org_id:b.org_id,verifier,expires_at:new Date(Date.now()+600000).toISOString()});
      if(saved.error)throw new Error("Could not start GitHub connection");
      const url=new URL("https://github.com/login/oauth/authorize");
      const base=(process.env.NEXT_PUBLIC_APP_URL||"https://threatcrush.com").replace(/\/$/,"");
      url.search=new URLSearchParams({client_id:process.env.GITHUB_CLIENT_ID,redirect_uri:base+"/api/auth/callback",scope:"read:user read:org",state,prompt:"select_account",code_challenge:createHash("sha256").update(verifier).digest("base64url"),code_challenge_method:"S256"}).toString();
      const r=response({url:url.toString()});r.cookies.set("tc_github_monitor_state",state,{httpOnly:true,secure:base.startsWith("https:"),sameSite:"lax",path:"/api/auth/callback",maxAge:600});return r;
    }
    if(b.action==="discover") {
      // Return verified identities' matching installations only. A different
      // customer's private GitHub installation must never reach this response.
      const links=await admin.from("github_monitoring_links").select("allowed_owners").eq("org_id",b.org_id);
      if(links.error)throw new Error("Could not load linked accounts");
      const allowed=new Set((links.data??[]).flatMap(l=>(l.allowed_owners as GitHubOwner[]).map(o=>o.id)));
      const [all,app]=await Promise.all([installations(),monitoringAppAccess()]);
      const found=all.filter(i=>allowed.has(i.account.id)).map(i=>({id:i.id,account_id:i.account.id,login:i.account.login,selection:i.repository_selection,suspended:Boolean(i.suspended_at),contents_read:canReadContents(i.permissions)}));
      return response({installations:found,app});
    }
    if(b.action==="enable") {
      if(!Array.isArray(b.owner_ids)||!b.owner_ids.length||b.owner_ids.length>100||b.owner_ids.some((id:unknown)=>!Number.isSafeInteger(id)))return response({error:"Choose GitHub accounts or organizations"},400);
      await enableOwners(admin,b.org_id,b.owner_ids);
      return response({enabled:true,message:"All accessible repositories are queued. New repositories are discovered automatically. Critical pages go to Owners + Admins."});
    }
    if(b.action==="defaults") {
      // One operation for every connected repo and account in the org.
      const a=await admin.from("github_monitoring_owners").update({silence_examples:true}).eq("org_id",b.org_id);
      const r=await admin.from("github_repository_policies").update({silence_examples:true,team_id:null,updated_at:new Date().toISOString()}).eq("org_id",b.org_id);
      if(a.error||r.error)throw new Error("Could not save organization defaults");
      return response({saved:true});
    }
    if(!isUuid(b.owner_id))return response({error:"Unknown monitoring action"},400);
    const owner=await admin.from("github_monitoring_owners").select("*").eq("id",b.owner_id).eq("org_id",b.org_id).maybeSingle();
    if(owner.error)throw new Error("Could not load monitoring account");
    if(!owner.data)return response({error:"Monitoring account not found"},404);
    if(b.action==="sync") {await discoverOwner(admin,owner.data as MonitoringOwner);return response({synced:true});}
    if(b.action==="retry") {
      const saved=await admin.from("github_monitoring_repositories").update({status:"queued",error:null,next_scan_at:new Date().toISOString()}).eq("owner_id",b.owner_id).eq("status","failed");
      if(saved.error)throw new Error("Could not retry scans");return response({queued:true});
    }
    if(b.action==="settings") {
      const patch:Record<string,boolean>={};
      for(const key of ["enabled","silence_examples","silence_warnings"])if(b[key]!==undefined){if(typeof b[key]!=="boolean")return response({error:"Settings must be booleans"},400);patch[key]=b[key];}
      if(!Object.keys(patch).length)return response({error:"No settings supplied"},400);
      const saved=await admin.from("github_monitoring_owners").update(patch).eq("id",b.owner_id).eq("org_id",b.org_id);
      if(saved.error)throw new Error("Could not save monitoring settings");return response({saved:true});
    }
    return response({error:"Unknown action"},400);
  } catch(e) {return response({error:e instanceof GitHubMonitorError?e.message:(e as Error).message},e instanceof GitHubMonitorError?e.status:500);}
}
