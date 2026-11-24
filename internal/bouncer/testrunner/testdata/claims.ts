// Allows a request when the session holds, or the operator grants, the
// repository claim named by the ?repo= query parameter.
import { defineFilter, deny, requestClaim } from "bouncer";

export default defineFilter({
  async onRequest(req, next) {
    const repo = req.query.get("repo") ?? "";
    if ((req.session?.claims.repository ?? []).includes(repo)) return next(req);
    if (await requestClaim("repository", repo, `allow ${repo}?`)) return next(req);
    return deny(`repository ${repo} is out of scope`);
  },
});
