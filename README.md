# makefun-github-core-clone-01

GitHub-compatible git forge: git smart HTTP (upload-pack v2, receive-pack v0),
REST v3, GraphQL v4, MCP. Single-file Node 22 entrypoint (`main.ts`), stdlib
only — no git binary, no outside service, no proxy.

Run: `node --experimental-strip-types main.ts` with `MAKEFUN_ENV_URL` and
`MAKEFUN_SHOP_TOKEN` set. The entry binds an ephemeral port, registers it
with the env, and exits 0 when the env reports done.
