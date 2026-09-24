# ccaguest
 
This repository contains a Rust-based command-line tool for the following ARM CCA attestation features:
 
- Evidence generation
- Evidence verification in remote and local mode
- Endorsements fetch
- Policy fetch and submission (TODO)
- Evidence, EAR, and endorsements display

## Command Tree
![Command Tree](./docs/command_tree.png)
Detailed explanation for each subcommand is in [UserGuide.md](UserGuide.md)
 
## Software Architecture

A summary of software architecture is given below.

### Remote verification

![Verify Remote](./docs/verify_remote.png)

The above diagram is simplified down to the most essential interactions. `ccaguest` connects to [Veraison's remote verification service](https://github.com/veraison/services/tree/main/verification) and establishes a challenge response session using [rust-apiclient](https://github.com/veraison/rust-apiclient). Using the nonce received from the remote verifier, it requests the Realm VM for an attestation report using [rust-regl](https://github.com/veraison/rust-regl) and sends it to the verifier.

Once the attestaion evidence has been verified, the received attestation results (EAR) is validated and shown to the relying party. It can also be saved to an output file and displayed later using the `ccaguest display` subcommand.

### Local verification

![Verify local](./docs/verify_local.png)

`ccaguest` uses [cover](https://github.com/veraison/cover) to locally verify an attestation report without connecting to a remote verification service. The endorsements can be queried from a [remote CoSERV service](https://github.com/veraison/tree/main/coserv) using [rust-apiclient](https://github.com/veraison/rust-apiclient).
 
>[!NOTE]
>While using the `tsm` backend for attester, `sudo` permissions are required for `ccaguest`. `tsm` backend uses linux kernel's `configfs-tsm-report` ABI to fetch the evidence. Hence the process must have sufficient privilege to write to `configfs`, which can be usually done by escalating the privilege using `sudo`. It can also be used within a non-realm VM and the attestation evidence can be retrieved from a Realm VM using `regl`'s `ratsd` backend without `sudo` permissions.

>[!NOTE]
> The CoSERV service used during local verification must support querying `collected` artifacts.

>[!NOTE]
> The base url must have empty path segment, e.g. "http://address:port", "https://veraison.example" or "https://veraison.example/" but not "https://veraison.example/foo".

## How to Build
 
This is a Rust-based CLI tool, so user need to [install Rust](https://rust-lang.org/tools/install/) first.

Build the project:

```
cargo build
```

The binary executable will be generated at `target/debug/ccaguest`.

Test the project:

```
cargo test
```

## Installation

Install the tool from the repository root directory:

```bash
cargo install --path . --locked
```

After installation, the `ccaguest` binary will be available on your system PATH.

## Quick Start 

Sample tokens are available in the `test/` directory. 

Display an example CCA token:

```bash
$ ccaguest display evidence -f test/cbor/ccatoken.cbor -p
{
  "cca-platform-token": {
    "cca-platform-profile": "tag:arm.com,2023:cca_platform#1.0.0",
    "cca-platform-challenge": "DSLgiphGkFhIYxgoNIm9s28J2+/rGGTfQz+m5U6i1xE=",
    ...
  },
  "cca-realm-delegated-token": {
    "cca-realm-profile": "tag:arm.com,2023:realm#1.0.0",
    "cca-realm-challenge": "bobW2XzHE7xt1D285JGmtAMRwCeov4WjnaY+nORMEyqKEZ0pb65qaZnpvz5EcbDOASRdiJQkwx6JeTs7HWsVBA==",
    ...
  }
}
[2026-07-22T10:56:08Z INFO  ccaguest] done.
```

List all available commands:

```bash
$ ccaguest --help
```
