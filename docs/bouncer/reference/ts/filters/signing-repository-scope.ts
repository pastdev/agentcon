// Scope commit and tag signing to the session's repositories.
//
// Attach this to a signer service. The agent's git-sign helper sends the
// repository it is signing for as ?repository=<host>/<path>, taken from the
// origin remote. That value is the agent's claim, not a fact. This filter
// checks it against the session's `repository` claims, which the host seeds.
//
// A held repository signs without a prompt. Any other asks the operator, who
// can allow it once or add it to the session. A request with no repository
// is denied.
//
// Git hosts treat host names and usually paths case-insensitively, so this
// filter lowercases the repository before comparing it or asking for it.
// Claims compare exactly, so seed the lowercase form.
//
// The signer itself refuses anything that is not an unsigned git commit or
// tag, so this filter does not look at the body.
import { defineFilter, deny, requestClaim } from "bouncer";

export default defineFilter({
  async onRequest(req, next) {
    if (req.transport !== "http" || req.method !== "POST" || req.path !== "/openpgp/sign") {
      return next(req);
    }
    const values = req.query.getAll("repository");
    if (values.length !== 1 || values[0] === "") {
      return deny("signing needs exactly one repository; set git config agentcon.signing.repository or an origin remote");
    }
    const repository = values[0].toLowerCase();
    if ((req.session?.claims.repository ?? []).includes(repository)) return next(req);
    const allowed = await requestClaim(
      "repository",
      repository,
      `Let the agent sign commits and tags for ${repository}?`,
    );
    return allowed ? next(req) : deny(`${repository} is not one of this session's repositories`);
  },
});
