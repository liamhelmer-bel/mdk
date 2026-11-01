# Fixed root bootstrap composition

`heterodyne-receiver-bootstrap` is a no-argument, empty-environment root entry.
It is installed separately at `/opt/heterodyne-receiver/bin/heterodyne-receiver-bootstrap`,
with its exact reviewed ELF digest and root ownership in the root installation
receipt. It does not add a fifth native ELF to the current release inventory.
Root's current explicit deployment instruction is recorded by the deployment
controller; parsed profile fields are not human consent or an admitted owner token.

The retained root launcher supplies these original descriptors before exec:

| FD | Exact input |
| --- | --- |
| 3 | root:root 0400 initializer.v2 profile, readonly |
| 4 | receiver899 generation parent directory, 0700 |
| 5 | receiver899 fresh initializer phase ledger, 0600 |
| 6 | root:root 0600 lifetime lease, same original OFD |
| 7 | root:root 0400 expiry profile, readonly |
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
