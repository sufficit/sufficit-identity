# Fleet review guidance for Sufficit Identity

In the Sufficit context, Fleet serves this repository for pull-request review.
Use the scope of the current mission. Review the exact PR head against the
generic product boundary in [PRODUCT.md](PRODUCT.md) and the relevant
[Identity documentation](docs/README.md).

Use the [testing instructions](README.md#testing) for the affected protocol.
Preserve compatibility and check tenant boundaries when claims or tokens
change. Use fictional consumer examples. Distinguish local protocol tests
from the external [OpenID conformance environment](conformance/README.md).

On resumption, reuse compatible review evidence and inspect the current CI
state. Record any remaining issue at the affected SHA. Report budget or
access blockers through Fleet's existing reviewer workflow.
