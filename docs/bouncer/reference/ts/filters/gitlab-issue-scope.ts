// Scope GitLab issue creation to the session's repositories.
//
// The host seeds each session with `repository` claims such as
// "gitlab.example.com/group/project" (host, then the project path). Creating
// an issue in one of those projects goes through without a prompt. Any other
// project asks the operator, who can allow it once or add it to the session.
//
// Claims compare exactly. Seed them as `<host>/<path>` with the path cased
// as clients send it in URLs.
//
// Requests whose project cannot be resolved to a path are denied rather than
// guessed at: numeric project IDs, and GraphQL `createIssue` mutations,
// which name projects by a separate field. Every other request continues.
import { defineFilter, deny, requestClaim } from "bouncer";

// POST /api/v4/projects/:id/issues, with an optional format suffix.
const issuesSegment = /^issues(\.json)?$/;

export default defineFilter({
  async onRequest(req, next) {
    if (req.path === "/api/graphql") {
      // A parse error rejects, which fails the request closed.
      const ops = (await req.graphql()) ?? [];
      if (ops.some((op) => op.type === "mutation" && op.fields.includes("createIssue"))) {
        return deny("issue creation through GraphQL is not allowed; use the REST API with the project path");
      }
      return next(req);
    }

    // Use rawPath: in the decoded path, "group%2Fproject" and
    // "group/project" look the same and the segment boundaries are lost.
    const segs = req.rawPath.replace(/\/+$/, "").split("/");
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

    const repository = `${req.host}/${project}`;
    if ((req.session?.claims.repository ?? []).includes(repository)) return next(req);
    const allowed = await requestClaim(
      "repository",
      repository,
      `Let the agent create issues in ${repository}?`,
    );
    return allowed ? next(req) : deny(`${repository} is not one of this session's repositories`);
  },
});
