# Presence reactions design

Implemented in the Hermes Marmot adapter. Both `presence_reactions` and
`approval_reactions` under `platforms.marmot.extra` default to false and work
independently. Neither changes sender authorization or activation policy.

Processing start adds 👀 to the admitted inbound message. Only queued messages
that pass activation and are not consumed by onboarding retarget active presence.
Completion adds ✅ to the original reply anchor, even after retargeting.

Hermes live-status signals map tool start to 🛠️ and tool completion to ⏳ between
tools. Active work cycles through 🛠️ 🔨 ⚙️ 🧱 after 120, 240, 480, then 600 seconds,
with a 600-second cap. Each new tool start resets the cycle. Concurrent tools keep
the cycle active until all complete. Turn end and disconnect cancel timers.
Emoji sets are configurable with `presence_emojis`.

The processing hook captures its event identity in a ContextVar. Hermes copies
that context into its agent executor. Status callbacks retain this original
identity; stale, cross-group, and uncorrelated callbacks are ignored. They never
read the current owner to manufacture correlation.

Reaction operations are queued, best-effort, and bounded to three attempts with
five-second per-attempt timeouts. One worker serializes each group's operations;
state and queues are bounded. Network failure cannot fail the turn. Only the
exact temporary presence reaction is removed, preserving consent reactions.

Regression tests use a fake daemon socket, fake timer, the inbound admission
path, and context-copying worker threads invoking the public status callback.
