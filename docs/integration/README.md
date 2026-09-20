# MDK client integration guides

Use these guides to upgrade an existing MDK client. They explain required compatibility
changes, new defaults, optional feature adoption and validation. They complement the
short [release notes](../release/) and the [current binding integration reference](../../crates/marmot-uniffi/README.md).

| Upgrade | Detailed guide | Release notes |
| --- | --- | --- |
| 0.10.2 → 0.10.3 | [0.10.3 integration](0.10.3.md) | [0.10.3 notes](../release/0.10.3.md) |
| 0.10.1 → 0.10.2 | [0.10.2 integration](0.10.2.md) | [0.10.2 notes](../release/0.10.2.md) |

Start at the guide matching the binary you are adopting. Read every intervening guide
when skipping versions; this series begins at 0.10.2 and does not replace older release
notes. New clients should first read the current binding README and complete method
reference, then the guide for their selected release.

Guides describe source contracts, not proof that artifacts have been published or that a
particular app has adopted them. Check release assets and their provenance separately.
A guide added after a tag is a documentation supplement: link to its merged documentation
commit, not a path under the older tag that does not contain it. Do not move release tags.

Authors: follow [Release documentation](../../release.md#release-documentation). Keep historical
guides scoped to their named cohort; explain later corrections without silently assigning
future behavior to an older release.
