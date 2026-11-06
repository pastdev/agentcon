import { defineFilter, deny } from "bouncer";
import { tag } from "smoke-tag";

export default defineFilter({
  name: "smoke-tag",
  onRequest(req, next) {
    if (req.query.get("raw") === "1") {
      return deny("raw response blocked by filter");
    }
    return next(req);
  },
  async onResponse(res) {
    if (res.status !== 200) {
      return;
    }
    const text = (await res.body.text()).trim();
    res.body.set(tag(text) + "\n");
  },
});
