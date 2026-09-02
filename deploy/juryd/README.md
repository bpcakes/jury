# `juryd` container example

> Jury is externally unreviewed pre-alpha software. It does not protect
> secrets and must not be used with real credentials.

Build from the repository root:

```console
$ docker build -f deploy/juryd/Dockerfile -t juryd:local .
```

Run the anchor image on the independently administered anchor host, mounting
its configuration read-only and its own state directory writable:

```console
$ docker run --read-only --user 10001:10001 \
    --mount type=bind,src=/etc/juryd-anchor,dst=/etc/juryd-anchor,readonly \
    --mount type=bind,src=/var/lib/juryd-anchor,dst=/var/lib/juryd-anchor \
    -p 8444:8444 juryd:local anchor serve \
    --config /etc/juryd-anchor/anchor.json
```

Run the witness image on a different host and authority boundary:

```console
$ docker run --read-only --user 10001:10001 \
    --mount type=bind,src=/etc/juryd,dst=/etc/juryd,readonly \
    --mount type=bind,src=/var/lib/juryd,dst=/var/lib/juryd \
    -p 8443:8443 juryd:local serve --config /etc/juryd/witness.json
```

All mounted private files and state directories must be owned by numeric UID
10001 and must not grant group/world permissions. Initialize databases with
the same image before serving. Do not use a shared Docker socket, host, volume,
administrator, backup target, restore credential, or orchestration account for
the two commands: separate containers alone do not satisfy the required
failure-domain and authority separation.
