# Recorded tenant policies

One file per tenant: a real policy GET as `show-policy NAME --save tests/fixtures/tenants/<tenant>.json` writes it,
with names, ids, principals, directories, hosts, domains and IP ranges replaced by placeholders (`sia/redact.py`
`scrub_identity`) and **every key, value type and field the tool does not know kept**. That shape is the observation:
which fields this tenant echoes that the tool never writes, how it spells an unset value, what its listing projection
carries.

`tests/test_tenant_fixtures.py` replays each file against the body the tool builds (`tests/fakes.py` `replay_echo`):
a create must converge, `plan --drift` must say `exists`, and the fake tenant's echo model must cover every condition
key the file carries. When a tenant surprises the tool in production, record it here **first** -- the failing test
is the bug report -- then fix the comparison.

Review a file before committing it: tags, time zones and free-text settings are kept as they are.
