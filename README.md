# veracity

Veracity is a command line tool providing support for inspecting the DataTrails native `MERKLE_LOG` verifiable data structures.

A general familiarity with _verifiable data structures_, and in particular binary merkle trees, would be advantageous, but is not required.

## Installation

Veracity provides native binaries for [Mac OS](#mac-install), [Linux](#linuxwsl-install) on the [releases](https://github.com/datatrails/veracity/releases) page.

_Note_: For The Windows Subsystem for Linux (WSL), use the Linux binaries.

| OS      | Platform  | Architecture |
| :------ | :-------- | -----------: |
| Mac     | `darwin`  | `arm64`      |
| Mac     | `darwin`  | `x86_64`     |
| Linux   | `linux`   | `arm64`      |
| Linux   | `linux`   | `x86_64`     |

1. Select the desired release from the [releases page](https://github.com/datatrails/veracity/releases).
1. Download the archive for your host platform
1. Extract the archive
1. Set the file permissions
1. Move the binary to a location on your PATH

Or, follow these commands to install the latest build.

### Mac Install

```console
PLATFORM=$(uname -s | tr [:upper:] [:lower:])
ARCH=$(uname -m)
cd $TMPDIR
curl -sLO https://github.com/datatrails/veracity/releases/latest/download/veracity_${PLATFORM}_${ARCH}.tar.gz
tar -xf veracity_${PLATFORM}_${ARCH}.tar.gz
chmod +x ./veracity
mv ./veracity $HOME/.local/bin/
veracity --help
```

### Linux/WSL Install

```console
PLATFORM=$(uname -s | tr [:upper:] [:lower:])
ARCH=$(uname -m)
cd /tmp
curl -sLO https://github.com/datatrails/veracity/releases/latest/download/veracity_${PLATFORM}_${ARCH}.tar.gz
tar -xf veracity_${PLATFORM}_${ARCH}.tar.gz
chmod +x ./veracity
mv ./veracity $HOME/.local/bin/
veracity --help
```

#### Troubleshooting

If `veracity --help` fails, check the following:

Confirm `$PATH` includes `.local/bin`.
Either add  the location to `$PATH`, or place veracity in an alternate location within an existing `$PATH`.

```console
# Check veracity exists in your $PATH
echo $PATH

# Add to the path
export PATH="$HOME/.local/bin:$PATH"
# reload the configuration
source ~/.bashrc

# Confirm which veracity binary is being used
which veracity
```

## Example Usage

### Environment Variables

The following samples use environment variables to simplify the commands:

```console
EVENT_ID=publicassets/87dd2e5a-42b4-49a5-8693-97f40a5af7f8/events/a022f458-8e55-4d63-a200-4172a42fc2aa
DATATRAILS_URL=https://app.datatrails.ai
PUBLIC_TENANT_ID=tenant/6ea5cd00-c711-3649-6914-7b125928bbb4
```

## Verifying A Single Event

The following steps verify the single public event [`a022f458-8e55-4d63-a200-4172a42fc2aa`](https://app.datatrails.ai/archivist/v2/publicassets/87dd2e5a-42b4-49a5-8693-97f40a5af7f8/events/a022f458-8e55-4d63-a200-4172a42fc2aa) using the DataTrails API.

Check the event details directly.

1. Download the event from the DataTrails ledger:

    ```console
    curl -sL $DATATRAILS_URL/archivist/v2/$EVENT_ID > event.json
    ```

1. Verify inclusion with `veracity`

    ```console
    cat event.json | \
        veracity --data-url $DATATRAILS_URL/verifiabledata \
        --tenant=$PUBLIC_TENANT_ID \
        --loglevel=INFO \
        verify-included
    ```

1. View the output, noting there are no verification errors

    ```output
    verifying for tenant: tenant/6ea5cd00-c711-3649-6914-7b125928bbb4
    verifying: 663 334 018fa97ef269039b00 2024-05-24T08:27:00.2+01:00 
    publicassets/87dd2e5a-42b4-49a5-8693-97f40a5af7f8/events/a022f458-8e55-4d63-a200-4172a42fc2aa
    leaf hash: bfc511ab1b880b24bb2358e07472e3383cdeddfbc4de9d66d652197dfb2b6633
    OK|663 334|[aea799fb2a8..., proof path nodes, ...f0a52d2256c235]
    ```

**Note:** _To minimize veracity output, remove `--loglevel`, checking the exit code of 0 (`echo $?`) for a successful verification._

The elided proof path at time of writing was:

```output
[aea799fb2a8c4bbb6eda1dd2c1e69f8807b9b06deeaf51b9e0287492cefd8e4c,
9f0183c7f79fd81966e104520af0f90c8447f1a73d4e38e7f2f23a0602ceb617, 
a21cb383d63896a9811f06ebd2094921581d8eb72f7fbef566b730958dc35f1, 
1ea08fd02da3633b72ef0b09d8ba4209db1092d22367ef565f35e0afd4b0fc3, 
85a9d55cf507ef85bd264f4db7228e225032c48da689aa8597e11059f45ab30, 
ab40107f7d7bebfe30c9cea4772f9eb3115cae1f801adab318f90fcdc204bdc, 
4ca607094ead6fcd23f52851c8cdd8c6f0e2abde20dca19ba5abc8aff70d0d1, 
a6d0fd8922342aafbba6073c5510103b077a7de9cb2d72fb652510110250f9e, 
fafc7edc434225afffc19b0582efa2a71b06a2d035358356df0a52d2256c235, 
737375d837e67ee7bce182377304e889187ef0f335952174cb5bf707a0b4788]
```

## Verify Tamper Resiliency

One of the many scenarios DataTrails prevents is tampering if and when information was written to the ledger.

1. To simulate backdating, the following backdates one of the events in the log:

    ```console
    sed -i -e 's/2024-05-24T07:27:00.200Z/2024-04-24T07:27:00.200Z/g' ./event.json
    ```

1. Re-verify inclusion with `veracity verify-included`, noting the error

    ```console
    cat event.json | \
        veracity --data-url $DATATRAILS_URL/verifiabledata \
        --tenant=$PUBLIC_TENANT_ID \
        --loglevel=INFO \
        verify-included
    ```

1. View the output

    ```output
    ...
    error: the entry is not in the log. for tenant tenant/6ea5cd00-c711-3649-6914-7b125928bbb4
    ```

## Verify All Events

The `veracity verify-included` command accepts the result of a DataTrails list events call.
This verifies the inclusion of each event in the returned list.

1. Pipe the `events` to veracity:

    ```console
    PUBLIC_ASSET_ID=publicassets/87dd2e5a-42b4-49a5-8693-97f40a5af7f8
    curl -sL $DATATRAILS_URL/archivist/v2/$PUBLIC_ASSET_ID/events | \
        veracity --data-url $DATATRAILS_URL/verifiabledata \
            --tenant=$PUBLIC_TENANT_ID \
            --loglevel=INFO \
            verify-included 
    ```

## Read a Selected Node From the Log

An example of reading a node associated with event, it's possible to visit [merkle log entry page](https://app.datatrails.ai/merklelogentry/87dd2e5a-42b4-49a5-8693-97f40a5af7f8/999773ed-cc92-4d9c-863f-b418418705ea?public=true) for event [999773ed-cc92-4d9c-863f-b418418705ea](https://app.datatrails.ai/archivist/publicassets/87dd2e5a-42b4-49a5-8693-97f40a5af7f8/events/999773ed-cc92-4d9c-863f-b418418705ea)

On the Merkle log entry page we can see the `MMR Index` field with a value of `916` which can be used with the `node` command to retrieve the leaf directly from the merklelog using following command:

```console
veracity --data-url $DATATRAILS_URL/verifiabledata \
    --tenant=$PUBLIC_TENANT_ID \
    node --mmrindex 916
```

The above command will output `c3323019fd1d325ac068d203c62007b504c5fa762446a9fe5d88e392ec96914b` which will match the value from the merkle log entry page.

## Anchoring The Accumulator To Bitcoin

This is for interoperating with OpenTimestamps, and with anchoring services such
as Markovian Protocol's. A MERKLE_LOG seal signs the accumulator under the
operator's key. It says who vouched for that log state; it does not say when
the state existed, against a clock the operator does not run. An OpenTimestamps
proof over the same bytes adds that, with a trust root nobody runs.

The accumulator needs no single hash, but an OpenTimestamps proof commits to
one. `accumulator-ots-hash` prints it - sha256 over `massifs.DetachedPayload`,
the peaks concatenated in accumulator order, which is the payload a checkpoint
receipt signs and the univocity contract verifies - and with `--ots` checks a
proof over it:

```
veracity accumulator-ots-hash --peaks peaks.hex
peaks: 3
accumulator digest: 0a3f00d3ffdbf0d2d8900814e5463931b951231289e2f9be38c0ad1fc9a99d2c

veracity accumulator-ots-hash --peaks peaks.hex --ots accumulator.payload.ots
anchored in bitcoin block <height>
that block's merkle root must be <merkle root>
```

The proof is parsed and walked in `ots/`, in process, with nothing outside the
standard library and no call to the stock `ots` client. Nothing fetches block
headers: veracity proves the proof commits to this accumulator and no other, and
names the block and the Merkle root that block must have. Comparing that root
with a header you trust is the step you keep.

What this gives you is existence and ordering in time. Not consistency, not
append-only, not inclusion. It sits beside the seal rather than replacing it.
`examples/bitcoin-anchor.sh` runs the whole loop, stamping with the stock client.

## General Use Commands

Additional Commands include:

* `node` - read a merklelog node
* `verify-included` - verify the inclusion of an event, or list of events, in the tenant's merkle log
* `watch` - discover recently active logs
* `replicate-logs` - create or update a local trusted replica of one more more tenants logs,
   accepts the output of `watch` as input.
* `accumulator-ots-hash` - for OpenTimestamps interop: print the sha256 of an accumulator's detached payload, and check an OpenTimestamps proof over it
* `receipt` - Generate a [COSE Receipt](https://www.ietf.org/archive/id/draft-ietf-cose-merkle-tree-proofs-07.html) of inclusion using the [MMRIVER profile](https://www.ietf.org/archive/id/draft-bryce-cose-merkle-mountain-range-proofs-00.html) for an entry.

For more information, please visit the [DataTrails documentation](https://docs.datatrails.ai/)
