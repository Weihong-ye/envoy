# UB copy Envoy extra IP design

## Goal

Allow the UB copy Envoy binary to select additional IPv4 peers for `AF_SMC` socket creation at
runtime, without changing the existing behavior for `141.61.17.202`, `141.61.17.204`,
`141.61.17.206`, and `141.61.17.208`.

This change is independent of the Envoy/UBSocket zero-copy work. The selected sockets continue to
use `IoSocketHandleImpl`; `LD_PRELOAD=libubsocket.so` supplies the UBSocket copy data path.

## Runtime interface

The optional environment variable is:

```text
ENVOY_UB_EXTRA_IPS=141.61.17.210,141.61.17.212
```

Its value is a comma-separated list of IPv4 addresses. Leading and trailing ASCII whitespace around
each entry is ignored. The four built-in addresses remain enabled whether the variable is unset,
empty, or populated. Duplicate entries have no additional effect.

The environment is parsed once per process. An unset or entirely empty value means "no extra IPs".
When the value is non-empty, an invalid entry or an empty entry created by consecutive/leading/trailing
commas is a configuration error and terminates startup with an error that identifies the environment
variable and invalid value. This prevents an intended UB connection from silently falling back to TCP
because of a typo.

## Socket selection

An address uses `AF_SMC` only when all of the following are true:

- the socket type is stream;
- the address type is IP;
- the IP version is IPv4;
- the address exactly matches a built-in address or an address from `ENVOY_UB_EXTRA_IPS`.

UDS, IPv6, loopback, wildcard, and unmatched IPv4 sockets preserve the existing socket path. Failure
to create a selected `AF_SMC` socket remains fail-closed and never silently falls back to TCP.

## Implementation boundaries

The address parsing and membership decision will be isolated in a small Linux-only helper used by
`SocketInterfaceImpl::socket`. No thrift, buffer, UDS, explicit zero-copy, or UBSocket library code is
changed. Existing uncommitted probe files in the worktree are preserved but excluded from this
feature's commit.

## Verification and artifact

Verification consists of focused tests for the built-in list, an added IP, multiple IPs, whitespace,
duplicates, unmatched addresses, and malformed input, followed by an optimized static Envoy build
with tcmalloc disabled. The deliverable is an AArch64 tar archive containing the Release/no-tcmalloc
Envoy binary, a checksum file, and a short runtime command example.
