# Migrating a policy to credential allow lists

Issue: https://github.com/pastdev/agentcon/issues/44 (Let credentials be limited to filter subrequests)

A policy written before this change fails to load.
Each failure names the key that replaces the old one.

## Credentials

Every credential needs `allow`.

```yaml
# before
credentials:
  github-pat:
    token: {source: keyring}
  signing:
    internal: true
    private_key: {source: provided}

# after
credentials:
  github-pat:
    allow: [agent]                 # add subrequest if a filter's lookups use it
    token: {source: keyring}
  signing:
    allow: [internal]
    private_key: {source: provided}
```

Pick the kinds this way.

- A token the agent uses: `[agent]`.
- A token the agent uses and a filter's `subrequest()` also uses through `inject`: `[agent, subrequest]`.
- A token only filter lookups may use: `[subrequest]`.
  Bind it to a route with a rule's `subrequest.credentials`.
- An SSH key: `[agent]`.
- An OpenPGP signing key: `[internal]`.

## HTTP services

`credential:` on an `http` service becomes `credentials:` plus `inject.credential`.
SSH services keep their singular `credential:`.

```yaml
# before
- name: github
  hosts: [github.com, api.github.com]
  credential: github-pat
  inject:
    bearer: true
    git: {basic: {username: x-access-token}}

# after
- name: github
  hosts: [github.com, api.github.com]
  credentials: [github-pat]
  inject:
    credential: github-pat
    bearer: true
    git: {basic: {username: x-access-token}}
```

A service with a credential but no `inject` only lists it in `credentials`.

## GitLab project lookups

A service whose rules use `gitlab_project` with a `path` and no `id` needs `lookup_credential`.

```yaml
- name: gitlab
  hosts: [gitlab.com]
  credentials: [gitlab]
  inject: {credential: gitlab, header: PRIVATE-TOKEN}
  lookup_credential: gitlab
```

The lookup now always sends `Authorization: Bearer`, where before it followed `inject`.

## Filters

`credential(name)` is gone.
A filter that needed a secret in a subrequest calls `placeholder(name)` and puts the string where the secret goes.

`placeholder(name)` now returns a new one-time string on each call.
It throws for a credential whose `allow` lacks `subrequest`.
A filter that copied the agent's `Authorization` header into a subrequest gets the service's `inject` credential, or none on a service without `inject`.

## Test specs

`expect_credential` becomes `expect_credentials`, a list of credential names compared as a set.

```yaml
# before
expect_credential: true
expect_credential: false

# after
expect_credentials: [github-pat]
expect_credentials: []
```
