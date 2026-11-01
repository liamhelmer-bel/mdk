# Fixed root bootstrap composition

`heterodyne-receiver-bootstrap` is a no-argument, empty-environment root entry.
It is installed separately at `/opt/heterodyne-receiver/bin/heterodyne-receiver-bootstrap`,
with its exact reviewed ELF digest and root ownership in the root installation
receipt. It does not add a fifth native ELF to the current release inventory.
Root's current explicit deployment instruction is recorded by the deployment
controller; parsed profile fields are not human consent or an admitted owner token.

The source-fixed host parent supplies these original descriptors before exec;
a standalone invocation without its private FD8/9 channel is unsupported:

| FD | Exact input |
| --- | --- |
| 3 | root:root 0400 initializer.v2 profile, readonly |
| 4 | receiver899 generation parent directory, 0700 |
| 5 | receiver899 fresh initializer phase ledger, 0600 |
| 6 | root:root 0600 lifetime lease, same original OFD |
| 7 | root:root 0400 expiry profile, readonly |
| 8 | host-parent-created credentialled SOCK_SEQPACKET, private bootstrap peer |
| 9 | sealed readonly 32-byte bootstrap nonce A |
| 13 | root-created original Product card profile |
| 14 | original complete Git archive |
| 15 | original literal Git commit object |
| 18 | original canonical DeploymentPacket bytes |

The last four inputs remain correlation/publication artifacts, not consent. The
receiver's existing InstalledProducer independently checks their exact Git proof,
immutable HTTPS publication, packet, and actual native group binding. Root never
opens SQLCipher or reads the generated key/seed. Missing real artifacts refuse
startup; no caller-supplied authority flag or fabricated packet is substituted.

The bootstrap creates a private mount namespace, makes propagation private, and
binds only the release's source-qualified `runtime-etc` over `/etc`, readonly with
nosuid/nodev. The namespace spans every child. Full installation verification
then checks that `/etc` is the same directory inode and validates the exact copied
configuration and ELF baseline. Host resolver configuration is unchanged.

The fixed state parent is `/var/lib/heterodyne/receiver-owner`, root:root 0700.
An exclusive generation directory contains phase records, protected generated
fresh/process profiles, receiver-owned journal/intent/cache directories, and a
separate root-owned anchor directory. A prior directory, partial write, issued
phase, or unknown outcome causes HOLD. No stale-file deletion, adoption,
rollback assertion, or automatic replay is implemented.

The bootstrap first runs the source-selected owner-init ELF under an owned PID
namespace. Owner-init in turn runs the initializer under another owned namespace.
Each positive handoff requires a kernel-credentialed original descriptor transfer,
normal child exit, and namespace cessation. Phase `01-initialized.json` contains
actual account, KeyPackage reference, and KeyPackage event ID only after genuine
native publication/readback; the deployment controller uses those exact facts for
the separately supported invitation. The bootstrap immediately prepares the fresh
listener so invitation need not race a later polling process.

The source-owned consumer helper creates its Unix stream only after dropping to
UID/GID898 with no supplementary groups. Its original receiver endpoint is passed
using authenticated SCM_RIGHTS. Every receiver namespace drops to UID/GID899. The
root supervisor retains both its original lifetime lease and the actual returned
storage lease across all child lifetimes. Internal child-parent pidfds do not
occupy the receiver's anchor FD9.

Fresh enrollment passes its exact original profile and all existing FD3..16
inputs. Only an exact nonce-bound actual enrollment frame followed by normal
child exit permits the permanent profile to be formed. Enrollment and transport
routing are taken from authenticated native output, never synthesized from group
names, counts, or native-ID hex. Permanent startup independently reopens and
checks the actual retained enrollment/journal and GroupBinding.

The permanent receiver receives its existing exact FD3..18 mapping. It performs
one finite deployment exchange, retains the actual nonce-bound result verbatim,
and is waited through namespace cessation. A process exit is cessation, never
approval. This composition is not a persistent arbitrary-operation server; it
does not add ordinary manager-task authority or create a deployment packet.

This source is not yet qualification of a real live join, transport policy,
publication, immutable installed runtime, or deployment. Those require the actual
combined reviewed bytes, source-created publication inputs, measured target group
capabilities, and the explicit deployment execution receipts.

### Concrete installation/index/profile assembly

`heterodyne-receiver-assemble` is a separate root-only read-only preparation
executable, outside the four runtime roles. Pin its source/binary alongside the
external bootstrap. It grants no consent and writes only canonical bytes to
stdout. It never copies, adopts, deletes or publishes a candidate.

1. Copy the complete normalized runtime (including finite `runtime-etc`) and the
   four exact reviewed ELF files into a new root-owned candidate. Preserve every
   compiled inventory row; executable files are0555, ordinary files0444, source
   directories0755 and protected config/empty-certs directories0555. Keep the
   candidate root0755, with no existing installation-index.json.
2. Supply canonical evidence JSON containing exactly `release_identity` and
   `external` (the sorted full independently measured OS baseline rows
   `{path,sha256,size}`). Run as root:

   ```sh
   heterodyne-receiver-assemble index /absolute/new-candidate < evidence.json > /root/new-index.json
   sha256sum /root/new-index.json
   ```

   This independently walks and hashes the entire candidate, checks the exact
   compiled complete source inventory and four finite native roles, derives
   source/lock hashes from the compiled inventory and native artifact hashes
   from actual bytes. The supplied external observations are correlation data;
   actual installed verification must independently reread them and resolve the
   complete ELF graph. Index generation alone does not qualify the OS baseline.
3. Under root's exclusive install procedure, copy that exact candidate to
   `/opt/heterodyne-receiver/releases/<index-sha256>` and the index to its
   `installation-index.json`, root:root0444, single link. Do not alter the tree
   after generating the index. Preserve original candidate/index evidence.
4. Supply canonical request JSON with exactly these operational selections:
   `request_sha256`, `storage_generation`, `group` (actual native MLS hex), sorted
   `operators`, `expected_welcomer`, `inbox_endpoints`, `key_package_endpoints`,
   `minimum_accepted_endpoints`, `deadline_unix_ms`, `wait_seconds`, and
   `expiry_profile_sha256`. Run:

   ```sh
   heterodyne-receiver-assemble profile /opt/heterodyne-receiver/releases/<index-sha256> < request.json > /root/new-initializer-profile.json
   ```

   This creates a private mount namespace, mounts only installed fixed config
   over `/etc`, and invokes the actual complete published installation/platform
   verifier. It derives the closed profile schema, UID899/GID899, UID898/GID898,
   installation reference, `admind-receiver-v1` template and exact policy digest. It
   reuses production deadline/relay/operator validation. Unknown request fields
   and caller overrides are refused. The output still needs root:root0400,
   single-link/O_RDONLY custody and the exact retained expiry descriptor.
5. Launch the fixed source-qualified `/opt/heterodyne-receiver/bin/heterodyne-receiver-host-parent`
   with no arguments, empty environment and original FD3..7/13..15/18 inputs from
   the table. It verifies fixed launch/admission profiles, creates private FD8/9
   and starts bootstrap itself. Direct bootstrap is an internal child interface,
   not a supported manual bypass. Original lease/ledger OFDs remain retained
   throughout; no reopen between children. Existing generation/ledger means
   reconciliation, not restart. Owner-init's initializer/KP path can separately
   be qualified under its own retained-FD supervisor; it does not itself authorize
   host admission or synthesize a Consumed response.

The assembly executable's libc/loader and root launcher remain part of the
external root deployment receipt. Runtime index roles remain exactly four.
Full positive installed bootstrap, real-group capability compatibility and
actual publication/MLS response are separate qualification; unit/root mechanical
checks do not establish them.

### Supervisor budgets and exact final result

The initializer's network timeout retains its original absolute profile deadline
and bounded network wait. Owner-init waits through that same deadline plus60s
cessation; the outer bootstrap additionally reserves600s for owner-init's final
complete installation reread plus60s cessation. Receiver phases use a separate
600s preflight allowance, their original1..300s network wait, and60s cessation.
These are finite resource watchdogs, not claims of an OS I/O worst-case bound.
A watchdog failure retains UNKNOWN and never asserts that publication/join did
not occur. Full installation checks remain mandatory.

The UID898 helper has no competing read timer. Bootstrap starts it after source
ELF selection and drops its own transferred stream endpoint before waiting, so
a dead receiver is observed as EOF. The one parent-owned watchdog kills/reaps
the helper on failure. Both fresh and permanent results use the duplicate-key/
float-refusing native-frame decoder; permanent success retains exact observed
bytes in the exclusive final result file, without canonical reserialization.

The host parent validates its combined bootstrap deadline before spawning the
bootstrap, so unsupported deadlines cannot start a generation first. Termination
requests SIGKILL and waits for actual owned process-group cessation before
releasing the lifetime lease. An uninterruptible kernel wait can retain this
lease indefinitely; resource watchdogs do not bound kernel cessation and there
is no unsafe timeout that releases custody while a child may remain alive.
