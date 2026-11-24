// Scope GitLab issue creation to the session's repositories.
//
// The host seeds each session with `repository` claims such as
// "gitlab.example.com/group/project" (host, then the project path). Creating
// an issue in one of those projects goes through without a prompt. Any other
// project asks the operator, who can allow it once or add it to the session.
//
// GitLab host names and project paths are case-insensitive, so this filter
// lowercases `<host>/<path>` before comparing it or asking for it. Claims
// themselves compare exactly, so the host must seed the same lowercase form,
// including values taken from operator-written configuration. A seed with
// capitals never matches.
//
// Requests that create an issue in a project the filter cannot resolve to a
// path are denied rather than guessed at:
// - numeric project IDs
// - REST issue move and clone, whose target is a numeric to_project_id
// Every other REST request continues.
//
// GraphQL mutations name their target project in arguments, and GitLab adds
// mutations that create issues over time. So GraphQL fails closed: queries
// continue, and a mutation or subscription is denied unless every field it
// calls is in allowMutations. List only mutations that cannot create an
// issue. Unparseable GraphQL is denied.
//
// config:
//   allowMutations: GraphQL mutation fields to let through (default: none)
import { defineFilter, deny, requestClaim } from "bouncer";

// POST /api/v4/projects/:id/issues, with an optional format suffix.
const issuesSegment = /^issues(\.json)?$/;

// POST /api/v4/projects/:id/issues/:iid/move or /clone.
const relocateSegment = /^(move|clone)(\.json)?$/;

interface Config {
  allowMutations?: string[];
}

export default defineFilter<Config>({
  async onRequest(req, next, ctx) {
    if (/^\/api\/graphql\/*$/.test(req.path)) {
      // A parse error rejects, which fails the request closed.
      const ops = (await req.graphql()) ?? [];
      const allowed = new Set(ctx.config.allowMutations ?? []);
      for (const op of ops) {
        if (op.type === "query") continue;
        const unlisted = op.fields.filter((f) => op.type !== "mutation" || !allowed.has(f));
        if (unlisted.length) {
          return deny(`GraphQL ${op.type} ${unlisted.join(", ")} is not in allowMutations`);
        }
      }
      return next(req);
    }

    // Use rawPath: in the decoded path, "group%2Fproject" and
    // "group/project" look the same and the segment boundaries are lost.
    const segs = req.rawPath.replace(/\/+$/, "").split("/");
    const isProjectIssues = segs[1] === "api" && segs[2] === "v4" && segs[3] === "projects" && segs[5] === "issues";
    if (req.method === "POST" && isProjectIssues && segs.length === 8 && relocateSegment.test(segs[7])) {
      return deny(`issue ${segs[7].replace(/\.json$/, "")} targets a project by numeric ID, which cannot be checked`);
    }
    const isCreate =
      req.method === "POST" &&
      segs.length === 6 &&
      segs[1] === "api" &&
      segs[2] === "v4" &&
      segs[3] === "projects" &&
      issuesSegment.test(segs[5]);
    if (!isCreate) return next(req);

    // A malformed escape throws, which fails the request closed.
    const project = decodeURIComponent(segs[4]);
    if (!project.includes("/")) {
      return deny(`project ${project} is not a path; use the URL-encoded project path, not its numeric ID`);
    }

    const repository = `${req.host}/${project}`.toLowerCase();
    if ((req.session?.claims.repository ?? []).includes(repository)) return next(req);
    const allowed = await requestClaim(
      "repository",
      repository,
      `Let the agent create issues in ${repository}?`,
    );
    return allowed ? next(req) : deny(`${repository} is not one of this session's repositories`);
  },
});
