// Refuse git pushes to a GitHub repo that has Actions secrets, over both
// HTTPS and SSH. A pushed branch can carry a changed workflow, and a
// workflow run on that push can read the repo's secrets. This filter keeps
// the agent from pushing anywhere that would hand it those secrets.
//
// Listing a repo's secrets needs more access than the agent's own token
// should have, so the lookup uses an elevated credential: one whose allow
// list has subrequest but not agent. The policy binds it to the lookup's
// route with a rule like this, and gives this filter placement the id the
// rule names:
//
//   - action: allow
//     methods: [GET]
//     github_repo: [myorg/myrepo]
//     github_subpaths: ["actions/secrets"]
//     subrequest:
//       filters: [github-ci-safety]
//       credentials: [github-audit]
//
// The lookup sends a one-time placeholder for that credential in
// Authorization. Bouncer replaces it only on that route, so the token never
// reaches any other. The response never reaches the agent: the filter reads
// only the count. A lookup that fails, is denied, or answers anything but
// 200 denies the push.
//
// Each lookup is a real request to GitHub made while the push waits, and
// counts against the elevated token's rate limit.
//
// config:
//   api:        API base URL (default "https://api.github.com")
//   credential: elevated credential to look up with (default "github-audit")
import { defineFilter, deny, placeholder, subrequest, type Git, type HttpRequest, type SshRequest } from "bouncer";

interface Config {
  api?: string;
  credential?: string;
}

async function check(req: HttpRequest | SshRequest, git: Git | null, cfg: Config) {
  if (req.subrequest) return null;
  if (git?.service !== "receive-pack") return null;
  const api = (cfg.api ?? "https://api.github.com").replace(/\/+$/, "");
  // git.repo is owner/repo, already matched by the rule this filter is on.
  const url = `${api}/repos/${git.repo}/actions/secrets?per_page=1`;
  const what = `Actions secrets lookup for ${git.repo}`;
  let r;
  try {
    r = await subrequest({
      url,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${placeholder(cfg.credential ?? "github-audit")}`,
      },
    });
  } catch (e) {
    return deny(`${what} failed: ${(e as Error).message}`);
  }
  if (r.denied) return deny(`${what} was denied: ${r.denied.reason}`);
  if (r.status !== 200) return deny(`${what} answered ${r.status}`);
  const body = (await r.body.json()) as { total_count?: unknown };
  if (typeof body.total_count !== "number") return deny(`${what} did not answer a count`);
  if (body.total_count > 0) {
    return deny(`${git.repo} has Actions secrets that a pushed workflow could read; ask a maintainer to push`);
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
