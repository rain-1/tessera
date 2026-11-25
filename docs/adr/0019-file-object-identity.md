# ADR-0019: File object identity: operator-registered logical slots under a held directory FD

- Status: Proposed (design). The race tests are not yet written.
- Spec: §4.1, §9.3. Open question "logical file slot identity".

## Decision
- The operator registers an object as (slot name, trusted root directory,
  relative leaf name). The broker opens the root directory once
  (`O_PATH|O_DIRECTORY`) and keeps the FD. The registered root must be owned
  by the broker uid, must not be writable by any sandbox, and must be on a
  local filesystem. The filesystem type is checked with `fstatfs`.
- An `ObjectId` names the *logical slot*, not an inode, because Replace
  (write a temporary file, `fsync`, `renameat2` into place, `fsync` the
  directory) changes the inode. The adapter records (dev, ino) of the
  current content for audit only.
- Every access uses
  `openat2(rootfd, leaf, RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV)`.
  It requires a regular file (`fstat` S_ISREG) and enforces size limits.
  Device nodes and absolute agent paths are never opened.
- ReadSnapshot returns bounded bytes, never a descriptor.

## Consequences
- The leaf is a single name component in a directory that only the broker
  can write, so rename races from sandboxes are impossible. Other host
  processes that mutate the directory are trusted, as part of the operator
  configuration, and this is documented.
