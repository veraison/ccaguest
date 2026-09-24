# ccaguest
 
`ccaguest` is a Rust-based command-line tool that provides following ARM CCA attestation capabilities:
 
- Evidence generation
- Evidence verification in remote and local mode
- Endorsements fetch
- Policy fetch and submission (TODO)
- Evidence, EAR, and endorsements display

## Pre-requisites

Before using `ccaguest`, ensure the following requirements are met:

- **Operating System:** Ubuntu 24.04 LTS
- **Rust Toolchain:** Rust 1.98.0 or later
- **Network Access:** Required to connect with remote services: CoSERV service, Verification service, Management service, REGL's ratsd
- **ARM-CCA Hardware:** Required only when using the `tsm` attester backend for generating evidence. To use the `tsm` backend, `ccaguest` needs `sudo` permissions. `tsm` backend uses linux kernel's `configfs-tsm-report` ABI to fetch the evidence. Hence the process must have sufficient privilege to write to `configfs`, which can be usually done by escalating the privilege using `sudo`.
- **veraison/ratsd:** Required to be running on ARM-CCA Hardware when using the `ratsd` backend for generating evidence. Source: https://github.com/veraison/ratsd

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
 
## Low Level Design Document

### Command Tree
![Command Tree](./docs/command_tree.png)

The following sections describe each subcommand in detail.

### 1. `ccaguest display evidence`

![ccaguest display evidence](./docs/lld_display_evidence.png)

REGL (Rust Evidence Generation Library) is used to collect and process attestation evidence from Trusted Execution Environment (TEE) platforms. For more information, see the REGL project:

https://github.com/veraison/rust-regl

This command uses REGL to decode and display the contents of a provided attestation evidence file.

To display ARM CCA attestation evidence, provide the CBOR-encoded evidence file using the --file (-f) option.

Example:
```Shell
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

Help:
```Shell
$ ccaguest display evidence -h
Display evidence

Usage: ccaguest display evidence [OPTIONS] --file <FILE>

Options:
  -f, --file <FILE>  Path to the evidence file in CBOR format
  -v, --verbose...   Increase logging verbosity
  -p, --pretty       Pretty print the output
  -q, --quiet...     Decrease logging verbosity
      --force        Force write if output exists
  -h, --help         Print help
```

### 2. `ccaguest display ear`

![ccaguest display evidence](./docs/lld_display_ear.png)

This command displays an Entity Attestation Result (EAR) from a provided EAR file.

Provide the EAR file using the --file (-f) option.

Example:
```Shell
$ ccaguest display ear -f test/json/ear.jwk -p
{
  "ear.verifier-id": {
    "build": "vsts 0.0.1",
    "developer": "https://veraison-project.org"
  },
  "eat_profile": "test",
  "iat": 1,
  "submods": {
    "test": {
      "ear.status": "none"
    }
  }
}
[2026-07-22T11:01:52Z INFO  ccaguest] done.
```

Help:
```Shell
$ ccaguest display ear -h
Display entity attestation results (EAR)

Usage: ccaguest display ear [OPTIONS] --file <FILE>

Options:
  -f, --file <FILE>  Path to the EAR file in JWK format
  -v, --verbose...   Increase logging verbosity
  -p, --pretty       Pretty print the output
  -q, --quiet...     Decrease logging verbosity
      --force        Force write if output exists
  -h, --help         Print help
```

### 3. `ccaguest fetch evidence`

![ccaguest display evidence](./docs/lld_fetch_evidence.png)

REGL currently supports three attester backends:

- ratsd - Connects to a RATSD daemon running on ARM-CCA hardware. Requires the --ratsd-url option.
- tsm - Generates evidence using the Linux `configfs-tsm` interface. Requires CCA-capable hardware and `sudo` permissions. `tsm` backend uses linux kernel's `configfs-tsm-report` ABI to fetch the evidence. Hence the process must have sufficient privilege to write to `configfs`, which can be usually done by escalating the privilege using `sudo`.
- sim - Generates a simulated CCA token from JSON claims and JWK files located under the test/json/ directory (cca-claims.json and iak.jwk).

Users can optionally provide a nonce for evidence generation. The nonce can be supplied in raw, hexadecimal, Base64, or Base64URL format. If no nonce is specified, a random nonce is generated automatically.

The generated evidence is written to the specified output file. If no output path is provided, the evidence is saved as evidence.cbor in the current working directory.

Example:
```Shell
$ ccaguest fetch evidence -a sim -p
[2026-07-22T11:05:49Z INFO  ccaguest::fetch::evidence] {
      "cca-platform-token": {
        "cca-platform-profile": "tag:arm.com,2023:cca_platform#1.0.0",
        "cca-platform-challenge": "PU8hmS4J+6OFzL6HbpqlMIsZtINOw0gBwN0UVSTedUo=",
        ...
      },
      "cca-realm-delegated-token": {
        "cca-realm-profile": "tag:arm.com,2023:realm#1.0.0",
        "cca-realm-challenge": "a2bORb91exe+J52cL7WfY02/6TYU6e3cEoA/uGqYg8a96LhtFn+fiBfV3rVBPqQVlRCjtjSVIwfx1JZJW5jsFg==",
        ...
      }
    }
[2026-07-22T11:05:49Z INFO  ccaguest::fetch::evidence] Evidence saved to: "evidence.cbor"
[2026-07-22T11:05:49Z INFO  ccaguest] done.
```

Help:
```Shell
$ ccaguest fetch evidence -h
Fetch evidence

Usage: ccaguest fetch evidence [OPTIONS]

Options:
  -a, --attester <ATTESTER>          Regl attester backend to use for evidence generation [default: ratsd] [possible values: ratsd, tsm, sim]
  -v, --verbose...                   Increase logging verbosity
  -q, --quiet...                     Decrease logging verbosity
      --ratsd-url <RATSD_URL>        URL of the RATSD daemon to connect to. Required when --attester is set to `ratsd`. Defaults to `http://localhost:8895`
      --sim-claims <SIM_CLAIMS>      Path to ARM CCA claims file (JSON format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/cca-claims.json`
      --sim-iak <SIM_IAK>            Path to ARM CCA iak file (JWK format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/iak.jwk`
      --nonce-raw <NONCE_RAW>        Path to a text file containing nonce as raw bytes
      --nonce-hex <NONCE_HEX>        A hex-encoded nonce passed as a string
      --nonce-b64 <NONCE_B64>        A base64-encoded nonce passed as a string
      --nonce-b64url <NONCE_B64URL>  A base64url-encoded nonce passed as a string
  -o, --output <OUTPUT>              Output file path. If not specified, the evidence will be saved to default `evidence.cbor` in the current working directory [default: evidence.cbor]
  -p, --pretty                       Pretty print the output
      --force                        Force write if output exists
  -h, --help                         Print help (see more with '--help')
```

### 4. `ccaguest fetch endorsements`

![ccaguest display evidence](./docs/lld_fetch_endorsements.png)

This command fetches endorsements from a [remote CoSERV service](https://github.com/veraison/tree/main/coserv).

Endorsements are fetched using one (or a combination) of the following inputs:

- Implementation ID (impl-id) to retrieve reference values.
- Instance ID (inst-id) to retrieve trust anchors.
- Evidence file, from which the implementation ID and instance ID are extracted automatically. This can be provided only if neither `impl-id` nor `inst-id` are given.

The user must specify the CoSERV server base URL. Optional parameters can be provided to configure TLS certs, local caching, and signing requirements.

The CoSERV service can return:

- Collected artifacts (default)
- Source artifacts
- Both collected and source artifacts

The result type can be selected using the `--result-type` option.

Users can request signed results by specifying the `--must-sign` option. The CoSERV service must be able to generate signed results in this case.

By default:

- Trust anchor CoSERV results are stored in coserv_ta.cbor
- Reference value CoSERV results are stored in coserv_rv.cbor

Both files are created in the current working directory unless alternative output paths are specified.

Example:
```Shell
$ ccaguest fetch endorsements -e test/cbor/ccatoken.cbor -S http://localhost:1234
[2026-07-22T11:09:14Z INFO  ccaguest::fetch::endorsements] Trust anchors saved to: "coserv_ta.cbor"
[2026-07-22T11:09:14Z INFO  ccaguest::fetch::endorsements] Reference values saved to: "coserv_rv.cbor"
[2026-07-22T11:09:14Z INFO  ccaguest] done.
```

>[!NOTE] \
>In this and the subsequent sections, CoSERV queries might be required. For the output examples, `ccaguest` uses the CCA profile: "tag:arm.com,2025:cca_platform#1.0.0". This is used because it's supported in Veraison CoSERV service as of today.

Help:
```Shell
$ ccaguest fetch endorsements -h
Fetch endorsements

Usage: ccaguest fetch endorsements [OPTIONS] --coserv-server <COSERV_SERVER>

Options:
  -E, --impl-id <IMPL_ID>              Implementation ID (as per [rfc4648](https://datatracker.ietf.org/doc/html/rfc4648), base64 Standard or URL Safe encoding, padding optional). Use this to fetch reference values
  -v, --verbose...                     Increase logging verbosity
  -I, --inst-id <INST_ID>              Instance ID (as per [rfc4648](https://datatracker.ietf.org/doc/html/rfc4648), base64 Standard or URL Safe encoding, padding optional). Use this to fetch trust anchors
  -q, --quiet...                       Decrease logging verbosity
  -e, --evidence <EVIDENCE>            Path to an evidence file in CBOR format. Use this to extract impl-id and inst-id and then fetch endorsements
  -S, --coserv-server <COSERV_SERVER>  The base URL to a CoSERV service. Coserv service should support the result-type=collected
  -t, --ca-cert <CA_CERT>              The path to an X509 certificate to bootstrap TLS handshakes with the CoSERV service
  -l, --local-cache <LOCAL_CACHE>      The path to the directory where local coserv results will be cached. If not specified, no local caching is performed, and all CoSERV requests will go to the server
      --must-sign                      The server MUST sign CoSERV results. The command fails if the server does not support signing
  -r, --result-type <RESULT_TYPE>      CoSERV Result type [default: collected] [possible values: collected, source, both]
      --output-ta <OUTPUT_TA>          Output file path for fetched trust anchor. If not specified, the trust anchor output will be saved to default `coserv_ta.cbor` in the current working directory [default: coserv_ta.cbor]
      --output-rv <OUTPUT_RV>          Output file path for fetched reference values. If not specified, the reference values will be saved to default `coserv_rv.cbor` in the current working directory [default: coserv_rv.cbor]
  -p, --pretty                         Pretty print the output
      --force                          Force write if output exists
  -h, --help                           Print help
```

### 5. `ccaguest verify local`

![ccaguest verify local](./docs/lld_verify_local.png)

This command performs local verification of an attestation evidence using the [`veraison/cover`](https://github.com/veraison/cover) library.

An evidence file in CBOR format can be provided, or it can be generated at runtime using one of the REGL backends.

Endorsements can be provided using CoSERV results files in CBOR format, or they can be fetched at runtime using a remote CoSERV service. If the second option is used, the user must specify the CoSERV server base URL. Optional parameters can be provided to configure TLS certs, local caching, and signing requirements.

An optional rego policy file can also be provided for additional verification and the evaluated Trust Vectors are provided under "custom" submod of the resulting EAR.

>[!NOTE] \
> The CoSERV service used during local verification must support querying `collected` artifacts.

The attestation result is written to the specified output file. If no output path is provided, the attestation result is saved as ear.json in the current working directory.

```Shell
$ ccaguest verify local --attester sim --coserv-server https://veraison.test.linaro.org:11443 -p 
[2026-09-07T09:32:04Z INFO  ccaguest::verify::local] ear: {
      "eat_profile": "arm-cca",
      "iat": 1788773524,
      "ear.verifier-id": {
        "developer": "https://veraison-project.org",
        "build": "cover 0.0.1"
      },
      "submods": {
        "platform": {
          "ear.status": "affirming",
          "ear.trustworthiness-vector": {
            "instance-identity": 2,
            "configuration": 2,
            "executables": 3,
            "file-system": 0,
            "hardware": 2,
            "runtime-opaque": 2,
            "storage-opaque": 2,
            "sourced-data": 0
          }
        },
        "realm": {
          "ear.status": "warning",
          "ear.trustworthiness-vector": {
            "instance-identity": 2,
            "configuration": 0,
            "executables": 33,
            "file-system": 0,
            "hardware": 0,
            "runtime-opaque": 2,
            "storage-opaque": 0,
            "sourced-data": 0
          }
        }
      },
      "eat_nonce": "q190sUNsMjh1DWFHJwVYoWq3IoYMUGP3_NfF8F-7B2PBSsqDj1MWgmT_B_4sK5twVtGoAysMoXA24nGLJEbH-Q",
      "ear.raw-evidence": "2QGPohmsylkF7tKERKEBOCKgWQWBqQpYIJdSfYpHj_fdZO5MScvX7yqqdEx1weih_l7Wk8GMytaWGQEAWCEBBwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRgZAQl4I3RhZzphcm0uY29tLDIwMjM6Y2NhX3BsYXRmb3JtIzEuMC4wGQlbGTADGQlcWCB_RUxGAgEBAAAAAAAAAAAAAwA-AAEAAABQWAAAAAAAABkJX42kAWlSU0VfQkwxXzICWCCaJx8qkWsLbubOyyQm8LMgbvB0V4vlXZvJT28_46uGqgVYIFN4eWMHU13z7I2LFaLi3FZBQZw9MGDP4yI4wPqXP3qjBmdzaGEtMjU2pAFnUlNFX0JMMgJYIFPCNOXoRytqxRwa4cqz_gb60FO-uOv9iXewEGVb_dPDBVggU3h5YwdTXfPsjYsVouLcVkFBnD0wYM_jIjjA-pc_eqMGZ3NoYS0yNTakAWVSU0VfUwJYIBEhz8zVkT8KY_7ECm_9ROpk-dwTXGZjS6AB0QvPQwKiBVggU3h5YwdTXfPsjYsVouLcVkFBnD0wYM_jIjjA-pc_eqMGZ3NoYS0yNTakAWZBUF9CTDECWCAVcbXseL1oUSv3gwu2oqRLIEfH31e85564ocDlvqClAQVYIFN4eWMHU13z7I2LFaLi3FZBQZw9MGDP4yI4wPqXP3qjBmdzaGEtMjU2pAFmQVBfQkwyAlggEBWbryYrQ6ktldtZ2uH3LGRRJzAWYeCjzk44spWpfFgFWCBTeHljB1Nd8-yNixWi4txWQUGcPTBgz-MiOMD6lz96owZnc2hhLTI1NqQBZ1NDUF9CTDECWCAQEi6Faz_NSfBjY2MXR2FJy3MKGqHPqtgYVSty9W1vaAVYIFN4eWMHU13z7I2LFaLi3FZBQZw9MGDP4yI4wPqXP3qjBmdzaGEtMjU2pAFnU0NQX0JMMgJYIKpnoWmwu6IXqgqoimU0aSDITEJEfDa6X36mX0IsH-XYBVgg8UtJh5BLy1gU5EWaBX7U0g9YpjMVIoinYSFNzSh4C1YGZ3NoYS0yNTakAWdBUF9CTDMxAlggLm0xpZg6kSUb-uWu-hwKGdi6PPYB0OinBrTPqWYaa4oFWCBTeHljB1Nd8-yNixWi4txWQUGcPTBgz-MiOMD6lz96owZnc2hhLTI1NqQBY1JNTQJYIKH7UObIb64Wee8zUSlv1nE0EaCM-N0XkKT9BfroaIFkBVggU3h5YwdTXfPsjYsVouLcVkFBnD0wYM_jIjjA-pc_eqMGZ3NoYS0yNTakAWlIV19DT05GSUcCWCAaJSQCly9gV_pTzBcrUrn_ymmOGDEfrNDzsG7KrveeFwVYIFN4eWMHU13z7I2LFaLi3FZBQZw9MGDP4yI4wPqXP3qjBmdzaGEtMjU2pAFpRldfQ09ORklHAlggmpKtvAzuOO9ljHHOGxv4xlZo8Wa_shNkTIlcyxrQeiUFWCBTeHljB1Nd8-yNixWi4txWQUGcPTBgz-MiOMD6lz96owZnc2hhLTI1NqQBbFRCX0ZXX0NPTkZJRwJYICOJAxgMwQTsLF2LPyDFvGGziewKln34zCCM3HzUVBdPBVggU3h5YwdTXfPsjYsVouLcVkFBnD0wYM_jIjjA-pc_eqMGZ3NoYS0yNTakAW1TT0NfRldfQ09ORklHAlgg5sIejSYP5xiC3r2zOdJAKiynZIUpvCMD9IZJvOA4ABcFWCBTeHljB1Nd8-yNixWi4txWQUGcPTBgz-MiOMD6lz96owZnc2hhLTI1NhkJYHg6aHR0cHM6Ly92ZXJhaXNvbi5leGFtcGxlLy53ZWxsLWtub3duL3ZlcmFpc29uL3ZlcmlmaWNhdGlvbhkJYUTPz8_PGQliZ3NoYS0yNTZYYKNhwCs7Q38DbohFdfjXsVLZo2VBhjGCzDVOgGvrjH-LlLExEjNnAdzaO-6J7gGARc7BvLnJCJA7iaCu5MvxHDNvLJsJDGWLm8iVeMKFumPyXOJ7BFVuGl9HPqi0osG63Rms0VkCUdKERKEBOCKgWQHkqApYQKtfdLFDbDI4dQ1hRycFWKFqtyKGDFBj9_zXxfBfuwdjwUrKg49TFoJk_wf-LCubcFbRqAMrDKFwNuJxiyRGx_kZAQl4HHRhZzphcm0uY29tLDIwMjM6cmVhbG0jMS4wLjAZrMtYQFRoZSBxdWljayBicm93biBmb3gganVtcHMgb3ZlciAxMyBsYXp5IGRvZ3MuVGhlIHF1aWNrIGJyb3duIGZveCAZrMxnc2hhLTI1NhmszVhupQECAzgiIAIhWDABfgFXA7nS-Kyy01vgTDPth-c-S4bJt422rQ_71TdFp2ZRj7b3KG0-Od4qaTbo5nwiWDDeHb-TSZOg2eT8xbvQl5U9000ojo315Qt5LHEYG-Srf7I-65_3feV_KpDLgaJ2_dsZrM5YIDETFKtzYgNQz3WINK5cZdnowtx_6-bn2WVLvoZOMA1JGazPhFggJNWwopbMBcvYBoxQZ8W9Rzt3Ddpq4IL-O6MKvj-aarFYIHiPwJC_xrjtkDFSuoQU5z2vW4x7seea1QKrBpm2We0WWCDaxGpYQV3DoA16dBhSAI6crmT1LQO592129LNkT-_EFlggMsavxiflVYXAMVU1nzMaDiJfaEDblH3Zbvq4G-JnGTkZrNBnc2hhLTI1Nlhgs9IIhBPL0K4CYz0VCoA1AmOuXU14EXi_2owfKKkddK_dVHbUaz7fli9d-L4g6-Lov4N1tEnZXJFC9j5c28_To6EXuPqIOUJ9lAtDRIjIiSoDOKIEivBFt44KtmaRk65B"
    }
[2026-09-07T09:32:04Z INFO  ccaguest::verify::local] EAR saved to: "ear.json"
[2026-09-07T09:32:04Z INFO  ccaguest] done.
```


```Shell
$ ccaguest verify local -h
Local verification

Usage: ccaguest verify local [OPTIONS]

Options:
  -e, --evidence <EVIDENCE>
          Path to an evidence file in CBOR format. If not provided, a new evidence will be generated at runtime using Regl. The nonce can be provided in either of the following forms: - A text file containing the raw nonce bytes. - A string containing a hex- or base64-encoded nonce. The argument for that includes the nonce encoding(--nonce_<raw | hex | base64 | base64url>). If the nonce is not exactly 64B long, it is truncated or right-padded with 0s to make it 64B long
  -v, --verbose...
          Increase logging verbosity
  -a, --attester <ATTESTER>
          Regl attester backend to use for evidence generation [default: ratsd] [possible values: ratsd, tsm, sim]
  -q, --quiet...
          Decrease logging verbosity
      --ratsd-url <RATSD_URL>
          URL of the RATSD daemon to connect to. Required when --attester is set to `ratsd`. Defaults to `http://localhost:8895`
      --sim-claims <SIM_CLAIMS>
          Path to ARM CCA claims file (JSON format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/cca-claims.json`
      --sim-iak <SIM_IAK>
          Path to ARM CCA iak file (JWK format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/iak.jwk`
      --nonce-raw <NONCE_RAW>
          Path to a text file containing nonce as raw bytes
      --nonce-hex <NONCE_HEX>
          A hex-encoded nonce passed as a string
      --nonce-b64 <NONCE_B64>
          A base64-encoded nonce passed as a string
      --nonce-b64url <NONCE_B64URL>
          A base64url-encoded nonce passed as a string
  -R, --reference-values <REFERENCE_VALUES>
          Path to the reference values file. Must be a CoSERV results file in CBOR format
  -T, --trust-anchor <TRUST_ANCHOR>
          Path to the trust anchor file. Must be a CoSERV results file in CBOR format
  -S, --coserv-server <COSERV_SERVER>
          The base URL to a CoSERV service if endorsements are not present locally. Coserv service should support the result-type=collected
  -t, --ca-cert <CA_CERT>
          The path to an X509 certificate to bootstrap TLS handshakes with the CoSERV service
  -l, --local-cache <LOCAL_CACHE>
          The path to the directory where local coserv results will be cached. If not specified, no local caching is performed, and all CoSERV requests will go to the server
      --must-sign
          The server MUST sign CoSERV results. The command fails if the server does not support signing
  -P, --policy <POLICY_PATH>
          Path to custom policy file for verification.
  -o, --output <OUTPUT>
          Output file path for writing the attestation results. If not specified, the attestation results will be saved to default `ear.json` in the current working directory [default: ear.json]
  -p, --pretty
          Pretty print the output
      --force
          Force write if output exists
  -h, --help
          Print help (see more with '--help')
```

### 6. `ccaguest verify remote`

![ccaguest verify remote](./docs/lld_verify_remote.png)

This command performs remote verification of an attestation evidence using [`veraison/services`](https://github.com/veraison/services).

The user must provide a verification service base URL. Optionally, TLS certs can be configured.

An evidence file in CBOR format can be provided, or it can be generated at runtime using one of the REGL backends.

The attestation result is written to the specified output file. If no output path is provided, the attestation result is saved as ear.jwt in the current working directory.

```Shell
$ ccaguest verify remote --verification-server https://localhost:8443 --attester sim -p
[2026-09-07T09:52:31Z INFO  ccaguest::verify::remote] ear: {
      "ear.verifier-id": {
        "build": "0.0.2608+f7d0bd7",
        "developer": "Veraison Project"
      },
      "eat_nonce": "ZvwdopqZuBCY3oD_XlWRsEjDnlK4TWUYkbOCAjwRV1HEhTfgVvQDAdJqwHWaZvil73OgQrCN2PMpsYoFziaQMA==",
      "eat_profile": "tag:github.com,2023:veraison/ear",
      "iat": 1788774751,
      "submods": {
        "ARM_CCA": {
          "ear.appraisal-policy-id": "policy:ARM_CCA",
          "ear.status": "contraindicated",
          "ear.trustworthiness-vector": {
            "configuration": 99,
            "executables": 99,
            "file-system": 99,
            "hardware": 99,
            "instance-identity": 99,
            "runtime-opaque": 99,
            "sourced-data": 99,
            "storage-opaque": 99
          },
          "ear.veraison.policy-claims": {
            "problem": "no trust anchor for evidence"
          }
        }
      }
    }
[2026-09-07T09:52:31Z INFO  ccaguest::verify::remote] EAR saved to: "ear.jwt"
[2026-09-07T09:52:31Z INFO  ccaguest] done.
```

```Shell
$ ccaguest verify remote -h
Remote verification

Usage: ccaguest verify remote [OPTIONS] --verification-server <VERIFICATION_SERVER>

Options:
  -S, --verification-server <VERIFICATION_SERVER>
          The base URL to a verification service
  -v, --verbose...
          Increase logging verbosity
  -q, --quiet...
          Decrease logging verbosity
  -t, --ca-cert <CA_CERT>
          The path to an X509 certificate to bootstrap TLS handshakes with the verification service
  -l, --local-cache <LOCAL_CACHE>
          The path to the directory where local verification discovery document will be cached. If not specified, no local caching is performed, and all disocvery document requests will go to the server
  -e, --evidence <EVIDENCE>
          Path to an evidence file in CBOR format. If not provided, a new evidence will be generated at runtime using Regl. The nonce can be provided in either of the following forms: - A text file containing the raw nonce bytes. - A string containing a hex- or base64-encoded nonce. The argument for that includes the nonce encoding(--nonce_<raw | hex | base64 | base64url>). If the nonce is not exactly 64B long, it is truncated or right-padded with 0s to make it 64B long
  -a, --attester <ATTESTER>
          Regl attester backend to use for evidence generation [default: ratsd] [possible values: ratsd, tsm, sim]
      --ratsd-url <RATSD_URL>
          URL of the RATSD daemon to connect to. Required when --attester is set to `ratsd`. Defaults to `http://localhost:8895`
      --sim-claims <SIM_CLAIMS>
          Path to ARM CCA claims file (JSON format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/cca-claims.json`
      --sim-iak <SIM_IAK>
          Path to ARM CCA iak file (JWK format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/iak.jwk`
      --nonce-raw <NONCE_RAW>
          Path to a text file containing nonce as raw bytes
      --nonce-hex <NONCE_HEX>
          A hex-encoded nonce passed as a string
      --nonce-b64 <NONCE_B64>
          A base64-encoded nonce passed as a string
      --nonce-b64url <NONCE_B64URL>
          A base64url-encoded nonce passed as a string
  -o, --output <OUTPUT>
          Output file path for writing the attestation results. If not specified, the attestation results will be saved to default `ear.jwt` in the current working directory [default: ear.jwt]
  -p, --pretty
          Pretty print the output
      --force
          Force write if output exists
  -h, --help
          Print help (see more with '--help')
```

### 7. `ccaguest submit policy`
Yet to be implemented.

### 8. `ccaguest fetch policy`
Yet to be implemented.

### 9. `ccaguest display endorsements`
Yet to be implemented.

>[!NOTE]
>While using the `tsm` backend for attester, `sudo` permissions are required for `ccaguest`. `tsm` backend uses linux kernel's `configfs-tsm-report` ABI to fetch the evidence. Hence the process must have sufficient privilege to write to `configfs`, which can be usually done by escalating the privilege using `sudo`. It can also be used within a non-realm VM and the attestation evidence can be retrieved from a Realm VM using `regl`'s `ratsd` backend without `sudo` permissions.

>[!NOTE]
> The base url must have empty path segment, e.g. "http://address:port", "https://veraison.example" or "https://veraison.example/" but not "https://veraison.example/foo".

