# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Compute registry and authorisation centre for the privacy-aware runtime.

A compute node is somebody's machine — the operator's own ``personal_node`` or a
``dedicated_worker`` — and the gateway is the only party that can say whether a
task may run there. The two halves are split on purpose:

``registry``    the facts: which nodes exist, what each declared it can do,
                how recently it was heard from, and which allocations are live;
``authorizer``  the decision: default deny, then policy, capability and the
                user's explicit approval — in that order, with every refusal
                written to ``compute_audit``.

"Default deny" is implemented literally: an unregistered node, a node that has
never sent a heartbeat, a capability nobody granted, an approval that is not a
JSON ``true`` — each is a refusal with its own named reason, and none of them
falls through to "probably fine". Registration is an operator action, not
something a heartbeat can self-serve, so a machine that merely knows the
gateway's URL cannot add itself to the fleet.
"""

__all__: list = []
