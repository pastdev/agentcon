// Allows a request when a subrequest to the URL in its "lookup" query
// parameter answers 200. Subrequests themselves pass through.
import { defineFilter, deny, subrequest } from "bouncer";

export default defineFilter({
  async onRequest(req, next) {
    if (req.subrequest) return next(req);
    const url = req.query.get("lookup");
    if (!url) return next(req);
    let r;
    try {
      r = await subrequest({ url, headers: { Accept: "application/json" } });
    } catch (e) {
      return deny("lookup failed: " + (e as Error).message);
    }
    if (r.denied) return deny("lookup denied: " + r.denied.reason);
    if (r.status !== 200) return deny("lookup answered " + r.status);
    return next(req);
  },
});
