# Private protected receiver recovery source

This source implements the genuinely approved 4jf4 clean-recovery contract (design
f5c24abf9a3def22937c90f98fecd1869c09e415). It is not an installed host authority,
public authenticated factory, runtime enrollment, or deployment permission.

The cumulative source follows reviewed semantic commit 311a6f30, then recovery
foundation 46bc7000, direct native merge capture 2d46751b, and globally ordered
journal integration 2aa4d3b. These recovery checkpoints have not independently
passed code review; they form one cumulative new recovery review scope.

The private fresh-join owner captures the actual original Welcome and native join
projection. The journal retains and independently anchors it before native ACK.
An exclusively owned stream retains record ordering, source/control records and
consumer antirollback anchors. Reopen hydrates actual native group state, checks
original enrollment and direct native unchanged-policy merge provenance, rebuilds
bounded disk-backed semantic indexes, and only then positively acknowledges exact
retained native pending application events. An authenticated final reply whose
semantic projection was interrupted is classified once from retained provenance;
its original wire is never re-ingested. Fully published unanswered asks can resume.
Partial publication, missing native provenance, mismatched pending plaintext,
unknown external effects, altered enrollment, and inconsistent anchors remain HOLD.

The Linux disk index is derived cache, not approval evidence. Rebuild streams all
protected records; normal continuation advances only new source bytes. At most 100
unanswered asks retain full live payloads. Terminal asks, candidates and removal
scope use bounded per-entry disk lookups; multi-ask objections retain compact scoped
conflicts. History has no lifetime count or byte cap and is not discarded. Selected
original payload reconstruction still scans protected history linearly; initial
rebuild creates many fsynced index files. No production throughput qualification or
constant-time history lookup is claimed. Real disk/write/fsync errors HOLD; arithmetic
bounds are not disk reservation or a free-space guarantee.

Finite expiry is read from an owned, unchanged protected descriptor pinned by the
enrollment profile hash and the actual operation's initial release/outage window.
Original timestamps and expiry survive reopen. Later recovery authority never
extends initial approval. This extractor is not full Product packet validation.

Actual causal tests use native OpenMLS/SQLite/Nostr peeler and signed adapter wires
with synthetic enrollment/profile and injected relay acceptance. They exercise real
Engine destruction/reconstruction and pending-event checks; they do not qualify
real endpoint delivery, host UID custody, filesystem import exclusion, protected
path openers, Product producer invocation, current remote-history completeness,
installed binary/source closure, or a production account enrollment. The original
fresh-join intent descriptor still requires an eventual protected O_EXCL/nofollow
owning opener. Existing unknown past joins cannot acquire provenance retroactively.

The explicitly ignored terminal-history stress fixture writes real hash-chained,
independently anchored fsynced records and reconstructs over 10,000 terminal asks
and the former 32 MiB boundary. Its generated records are mechanical synthetic
history, not authenticated native joins/approvals or measured production throughput.
Run it separately with the exact ignored-test command recorded in the packaged
qualification; a pending or older-source run is not a final-source PASS.

Private transport ownership remains a non-wasm cgka-engine layering deviation
inherited from the reviewed semantic slice. Normal production source is exercised,
not hidden behind cfg(test). Protected APIs remain dormant and unexported.

## Round-one correctness repair

The actual cumulative HIGH review requested changes; it is retained unchanged.
Original and one-use consume records now retain the source-owned clock check used
for that transition. A later write/fsync timestamp cannot change an already checked
transition into an unreplayable one. Legacy records without the new checked-time
field retain their stricter historical replay check. Completed Consumed and Denied
states never turn into Expired; an unused Approved permission still expires.
Contrary evidence remains meaningful after consumption, including after expiry.
Expired candidates are no-ops before projection, including a final native outcome
recovered after downtime. Multi-card objections retain every scoped removal target,
including references whose original reply has not arrived yet.

Native merge/join capture failures after durable commit invalidate the capture and
provide no owning authority. They no longer bypass normal native in-memory epoch,
routing, cache and pending-event finalization. The owner still refuses an invalid
capture with the original effect retained; it never retries a committed wire.
Linux derived cache opens use the target architecture's libc O_NOFOLLOW constant.
No new dependency version is introduced; libc was already workspace/lock pinned.

Causal regressions include actual clock/write expiry crossings, consumed and denied
terminal state after expiry, later contrary evidence on consumed consent, actual
multi-card early removal, recovered native reply expiry, actual postcommit join and
merge capture failures, and a cache symlink that cannot read or alter its target.
Linear history lookup, fsynced disposable cache rebuild cost, and duplicated strict
readback validation remain disclosed improvements rather than new qualification.


## Round-two correctness repair and retained crash limits

Expiry preserves an enclosing classification hold; a failed outer transition cannot
become usable simply because an unrelated ask expired. Clean reopen checks all
actual native pending events against the retained original Welcome and positively
recorded application projections before catalog reconstruction can append decisions,
conflicts, removals or expiry. Only after successful semantic reconstruction does
the exclusive owner delete exactly the prechecked pending event IDs. No native
ingress runs between check and acknowledgment.

Card-complete and consumed transitions currently require two separately fsynced
ordered records (semantic transition, then control/one-use anchor transition).
A process or I/O failure between those records leaves an incomplete semantic
boundary. Reconstruction refuses it with HOLD; it does not replay, consume again,
or infer the missing terminal control. This accepted PoC crash-window limitation
requires authenticated recovery rather than ordinary clean reopen. The chain alone
does not make those two writes torn-write-free.

Protected join/merge capture is an observational authority guard outside the
OpenMLS transaction, an explicit exception to the general atomic native projection
rule. Failure after durable native commit invalidates the protected capture and
holds the receiver while ordinary native finalization continues. No protected
receipt is granted and no original wire is retried. The private reopen transport
parameter also retains the existing non-wasm transport-layering exception; no
production authority or new external constructor is claimed.
