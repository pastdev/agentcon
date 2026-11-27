// Refuse git pushes that GitHub's current branch rules would refuse, over
// both HTTPS and SSH. Before forwarding a push, it looks up the rules that
// apply to each pushed branch with
// GET /repos/{owner}/{repo}/rules/branches/{branch}. That endpoint reports
// rulesets, which need only read access. Classic branch protection is not
// included.
//
// GitHub enforces rulesets on its own. This filter matters when the token's
// owner can bypass them: GitHub's protections apply to the token's owner,
// and it cannot tell the agent from that person. A repo admin on a bypass
// list may push to a protected branch, and so would an agent using that
// admin's token. This filter applies the rules to the agent regardless.
// Without a bypass, it only refuses the push earlier with a clearer reason.
//
// The lookup is a subrequest. It goes through the policy of the service its
// host matches, as this session, so that service must allow it and inject
// its credential. A lookup that fails, is denied, or answers anything but
// 200 denies the push.
//
// config:
//   api:   API base URL (default "https://api.github.com")
//   block: rule types that refuse each kind of update
//          (default {create: [creation], update: [update, pull_request], delete: [deletion]})
import { defineFilter, deny, subrequest, type Git, type HttpRequest, type SshRequest } from "bouncer";

type UpdateType = "create" | "update" | "delete";

interface Config {
  api?: string;
  block?: Partial<Record<UpdateType, string[]>>;
}

const defaultBlock: Record<UpdateType, string[]> = {
  create: ["creation"],
  update: ["update", "pull_request"],
  delete: ["deletion"],
};

// Encode each segment so a branch like "feature/x#1" stays one path, with
// its slashes intact, and cannot add a query or fragment.
function branchPath(branch: string): string {
  return branch.split("/").map(encodeURIComponent).join("/");
}

async function rulesFor(api: string, repo: string, branch: string): Promise<string[] | string> {
  const url = `${api}/repos/${repo}/rules/branches/${branchPath(branch)}?per_page=100`;
  let r;
  try {
    r = await subrequest({ url, headers: { Accept: "application/vnd.github+json" } });
  } catch (e) {
    return `branch rules lookup for '${branch}' failed: ${(e as Error).message}`;
  }
  if (r.denied) return `branch rules lookup for '${branch}' was denied: ${r.denied.reason}`;
  if (r.status !== 200) return `branch rules lookup for '${branch}' answered ${r.status}`;
  const rules = (await r.body.json()) as { type: string }[];
  return rules.map((rule) => rule.type);
}

async function check(req: HttpRequest | SshRequest, git: Git | null, cfg: Config) {
  // This filter's own lookups are API requests, not pushes. A filter that
  // also runs on API requests would skip its work for them like this.
  if (req.subrequest) return null;
  if (git?.service !== "receive-pack") return null;
  const api = (cfg.api ?? "https://api.github.com").replace(/\/+$/, "");
  const block = { ...defaultBlock, ...cfg.block };
  const looked = new Map<string, string[] | string>();
  for (const u of await git.refUpdates()) {
    if (!u.ref.startsWith("refs/heads/")) continue;
    const branch = u.ref.slice("refs/heads/".length);
    if (!looked.has(branch)) looked.set(branch, await rulesFor(api, git.repo, branch));
    const rules = looked.get(branch)!;
    if (typeof rules === "string") return deny(rules);
    const hit = rules.find((t) => (block[u.type] ?? []).includes(t));
    if (hit) return deny(`GitHub rule '${hit}' protects branch '${branch}'; push a feature branch and open a pull request`);
  }
  return null;
}

export default defineFilter<Config>({
  async onRequest(req, next, ctx) {
    return (await check(req, req.git, ctx.config)) ?? next(req);
  },
  async onSSH(req, next, ctx) {
    return (await check(req, req.git, ctx.config)) ?? next(req);
  },
});
