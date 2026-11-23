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
// Requests that create an issue in a project the filter cannot resolve to a
// path are denied rather than guessed at:
// - numeric project IDs
// - REST issue move and clone, whose target is a numeric to_project_id
// - GraphQL mutations that create issues, which name their target in
//   arguments
// Every other request continues.
//
// The GraphQL list below is a denylist of known issue-creating mutations, so
// it must keep up with GitLab. For a hard guarantee, pair this filter with a
// GraphQL allowlist, as github-graphql-guard.ts does for GitHub.
import { defineFilter, deny, requestClaim } from "bouncer";

// POST /api/v4/projects/:id/issues, with an optional format suffix.
const issuesSegment = /^issues(\.json)?$/;

// POST /api/v4/projects/:id/issues/:iid/move or /clone.
const relocateSegment = /^(move|clone)(\.json)?$/;

// GraphQL mutations that create an issue, or an Issue-typed work item, in a
// project named by their arguments. The alert mutations may create an issue
// as a side effect.
const issueMutations = new Set([
  "createIssue",
  "workItemCreate",
  "workItemCreateFromTask",
  "issueMove",
  "createAlertIssue",
  "createTestCase",
  "alertSetAssignees",
  "alertTodoCreate",
]);

export default defineFilter({
  async onRequest(req, next) {
    if (req.path === "/api/graphql") {
      // A parse error rejects, which fails the request closed.
      const ops = (await req.graphql()) ?? [];
      for (const op of ops) {
        if (op.type !== "mutation") continue;
        const hit = op.fields.find((f) => issueMutations.has(f));
        if (hit) {
          return deny(`issue creation through GraphQL (${hit}) is not allowed; use the REST API with the project path`);
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
