#!/usr/bin/env python3
"""Owned local SQL rehearsal; never accepts production database endpoints."""
import argparse
import json
import os
import re
from pathlib import Path
import selectors
import subprocess
import time
import uuid


def command(*args, timeout=60, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({args[0]}): {result.stderr[-2000:]}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="mariadb@sha256:22edfe1c78349f8cae88bbb5c2873b7e6c515be767c91c691308ce57445806f3")
    parser.add_argument("--identity-tests", action="store_true", help="Run the built Release Identity Galera session integration test")
    parser.add_argument("--weighted-quorum", action="store_true", help="Rehearse owned four-node weighted quorum loss and recovery")
    args = parser.parse_args()
    if args.identity_tests and args.weighted_quorum:
        parser.error("--identity-tests and --weighted-quorum are separate rehearsals")
    prefix = "identity-galera-" + uuid.uuid4().hex[:8]
    network = prefix + "-net"
    nodes = [prefix + "-" + str(i) for i in range(4 if args.weighted_quorum else 3)]
    created = []
    lock = None
    network_created = False
    weights = [2, 1, 1, 2]
    # Disposable credentials, used only inside containers on this owned network.
    client = ["mysql", "-uroot", "-pdisposable-local-only", "--batch", "--skip-column-names", "--unbuffered"]

    def sql(node, query, check=True):
        return command("docker", "exec", node, *client, "-e", query, timeout=30, check=check)

    def ready(node, size):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            result = sql(node, "SHOW GLOBAL STATUS WHERE Variable_name IN ('wsrep_ready','wsrep_cluster_size','wsrep_local_state_comment');", check=False)
            fields = dict(line.split("\t", 1) for line in result.stdout.splitlines() if "\t" in line)
            if fields.get("wsrep_ready") == "ON" and fields.get("wsrep_cluster_size") == str(size) and fields.get("wsrep_local_state_comment") == "Synced":
                return
            time.sleep(0.5)  # Bounded infrastructure readiness polling, not an elapsed-time assertion.
        raise RuntimeError(f"Owned Galera node did not become ready: {node}")

    try:
        command("docker", "network", "create", *([] if args.identity_tests else ["--internal"]), network)
        network_created = True
        for i, node in enumerate(nodes):
            command("docker", "create", "--name", node, "--network", network,
                    *(["--publish", "127.0.0.1::3306"] if args.identity_tests else []),
                    "--env", "MYSQL_ROOT_PASSWORD=disposable-local-only", args.image,
                    "--wsrep-on=ON", "--wsrep-provider=/usr/lib/galera/libgalera_smm.so",
                    "--wsrep-cluster-name=" + prefix,
                    "--wsrep-cluster-address=gcomm://" + (nodes[0] if i else ""),
                    "--wsrep-node-name=" + node,
                    "--wsrep-sst-method=rsync", "--binlog-format=ROW",
                    "--default-storage-engine=InnoDB", "--innodb-autoinc-lock-mode=2",
                    *(["--wsrep-dirty-reads=ON"] if args.identity_tests or args.weighted_quorum else []),
                    "--wsrep-sync-wait=14", "--wsrep-provider-options=repl.causal_read_timeout=PT2S" +
                    (";pc.weight=" + str(weights[i]) if args.weighted_quorum else ""))
            created.append(node)
            command("docker", "start", node)
            ready(node, i + 1)
        for node in nodes:
            ready(node, len(nodes))
        version = sql(nodes[0], "SELECT VERSION(); SHOW GLOBAL STATUS LIKE 'wsrep_provider_version';").stdout.strip()
        if args.weighted_quorum:
            def status(node):
                result = sql(node, "SET SESSION wsrep_sync_wait=0; SHOW GLOBAL STATUS WHERE Variable_name IN ('wsrep_cluster_status','wsrep_cluster_size','wsrep_cluster_weight');")
                return dict(line.split("\t", 1) for line in result.stdout.splitlines() if "\t" in line)

            def non_primary(node):
                deadline = time.monotonic() + 120
                while time.monotonic() < deadline:
                    observed = status(node)
                    if observed.get("wsrep_cluster_status") == "non-Primary":
                        return observed
                    time.sleep(0.5)  # Poll membership, never assert an elapsed delay.
                raise RuntimeError("Owned minority did not lose primary status")

            causal = "SET SESSION wsrep_dirty_reads=OFF; SET SESSION wsrep_sync_wait=15; "
            initial = status(nodes[1])
            assert initial["wsrep_cluster_weight"] == "6", initial
            sql(nodes[1], "CREATE DATABASE rehearsal; CREATE TABLE rehearsal.sessions (id INT PRIMARY KEY) ENGINE=InnoDB; INSERT INTO rehearsal.sessions VALUES (1);")
            for node in nodes:
                assert sql(node, causal + "SELECT COUNT(*) FROM rehearsal.sessions;").stdout.strip() == "1"
            # Pause only owned containers: the first failure leaves weight 4/6.
            command("docker", "pause", nodes[0])
            for node in nodes[1:]:
                ready(node, 3)
            majority = status(nodes[1])
            assert majority["wsrep_cluster_weight"] == "4", majority
            sql(nodes[1], causal + "DELETE FROM rehearsal.sessions WHERE id=1;")
            assert sql(nodes[2], causal + "SELECT COUNT(*) FROM rehearsal.sessions;").stdout.strip() == "0"
            # Lose weight 2 from that accepted weight-4 component: half is not a majority.
            command("docker", "pause", nodes[3])
            minorities = [non_primary(node) for node in nodes[1:3]]
            rejection_codes = []
            for node in nodes[1:3]:
                rejected = sql(node, causal + "SELECT COUNT(*) FROM rehearsal.sessions;", check=False)
                # The causal wait may expire before the non-primary SQL rejection.
                error = re.search(r"ERROR (\d+) ", rejected.stderr)
                assert rejected.returncode != 0 and error and error[1] in {"1047", "1205"}, rejected.stderr
                rejection_codes.append(error[1])
                # Legacy dirty reads still answer from a non-primary component.
                assert sql(node, "SET SESSION wsrep_dirty_reads=ON; SET SESSION wsrep_sync_wait=0; SELECT COUNT(*) FROM rehearsal.sessions;").stdout.strip() == "0"
            command("docker", "unpause", nodes[3])
            for node in nodes[1:]:
                ready(node, 3)
            assert sql(nodes[2], causal + "SELECT COUNT(*) FROM rehearsal.sessions;").stdout.strip() == "0"
            command("docker", "unpause", nodes[0])
            recovery_errors = []
            for node in nodes:
                ready(node, 4)
                deadline = time.monotonic() + 60
                while True:
                    result = sql(node, causal + "SELECT COUNT(*) FROM rehearsal.sessions;", check=False)
                    if result.returncode == 0:
                        # Never retry a successful but stale answer.
                        assert result.stdout.strip() == "0", result.stdout
                        break
                    error = re.search(r"ERROR (\d+) ", result.stderr)
                    assert error and error[1] in {"1047", "1205"}, result.stderr
                    recovery_errors.append({"node": nodes.index(node), "error": error[1]})
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Owned causal read did not recover: " + result.stderr)
                    time.sleep(0.5)
            # A resumed process can initially expose an old membership snapshot.
            for node in nodes:
                ready(node, 4)
            recovered = status(nodes[1])
            assert recovered["wsrep_cluster_weight"] == "6", recovered
            print(json.dumps({"image": args.image, "version": version, "weights": weights,
                              "initial": initial, "after_first_loss": majority,
                              "after_second_loss": minorities, "causal_minority_read_errors": rejection_codes,
                              "legacy_dirty_read": "accepted", "recovery_errors": recovery_errors, "recovered": recovered,
                              "revoked_row_after_recovery": "absent on all four nodes"}))
            return
        if args.identity_tests:
            endpoints = []
            for node in nodes[:2]:
                address = command("docker", "port", node, "3306/tcp").stdout.strip()
                if not address.startswith("127.0.0.1:"):
                    raise RuntimeError("Owned SQL port is not loopback")
                endpoints.append("Server=127.0.0.1;Port=" + address.split(":")[1] +
                                 ";User=root;Password=disposable-local-only;Pooling=false;Default Command Timeout=10")
            env = dict(os.environ, IDENTITY_TEST_OWNED_GALERA_CONNECTIONS="|".join(endpoints))
            subprocess.run(["dotnet", "test", "src/tests/Sufficit.Identity.Tests.csproj", "-c", "Release",
                            "--no-build", "--no-restore", "--filter", "FullyQualifiedName~SessionTicketGaleraIntegrationTests",
                            "--nologo", "--verbosity", "quiet", "--logger", "console;verbosity=normal"], env=env,
                           cwd=Path(__file__).resolve().parent.parent, check=True, timeout=180)
            print(json.dumps({"version": version, "identity_test": "passed"}))
            return
        sql(nodes[0], "CREATE DATABASE rehearsal; CREATE TABLE rehearsal.sessions (id INT PRIMARY KEY) ENGINE=InnoDB; INSERT INTO rehearsal.sessions VALUES (1);")
        assert sql(nodes[1], "SET SESSION wsrep_sync_wait=15; SELECT COUNT(*) FROM rehearsal.sessions;").stdout.strip() == "1"
        # Freeze application of remote writes on one local node while allowing reads.
        sql(nodes[1], "SET GLOBAL wsrep_desync=ON;")
        lock = subprocess.Popen(["docker", "exec", "-i", nodes[1], *client],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        lock.stdin.write("SET SESSION wsrep_sync_wait=0; FLUSH TABLES WITH READ LOCK; SELECT 'locked';\n")
        lock.stdin.flush()
        # Bound the lock acknowledgement itself; no production locks exist.
        with selectors.DefaultSelector() as selector:
            selector.register(lock.stdout, selectors.EVENT_READ)
            if not selector.select(30):
                raise RuntimeError("Owned lock session did not acknowledge readiness")
        assert lock.stdout.readline().strip() == "locked"
        sql(nodes[0], "DELETE FROM rehearsal.sessions WHERE id=1;")
        stale = sql(nodes[1], "SET SESSION wsrep_sync_wait=14; SELECT COUNT(*) FROM rehearsal.sessions;").stdout.strip()
        assert stale == "1", f"Expected reproducible stale row, received {stale!r}"
        blocked = sql(nodes[1], "SET SESSION wsrep_sync_wait=15; SELECT COUNT(*) FROM rehearsal.sessions;", check=False)
        assert blocked.returncode != 0 and "1205" in blocked.stderr, blocked.stderr
        lock.stdin.write("UNLOCK TABLES; quit\n")
        lock.stdin.flush()
        lock.communicate(timeout=15)
        lock = None
        sql(nodes[1], "SET GLOBAL wsrep_desync=OFF;")
        causal = sql(nodes[1], "SET SESSION wsrep_sync_wait=15; SELECT COUNT(*) FROM rehearsal.sessions;").stdout.strip()
        assert causal == "0", f"Revoked row still visible: {causal!r}"
        print(json.dumps({"image": args.image, "version": version, "nodes": 3,
                          "stale_select_with_14": stale, "barrier_with_15": "1205 while apply blocked",
                          "select_after_unblock_with_15": causal}))
    finally:
        if lock is not None:
            lock.kill()
            lock.communicate(timeout=10)
        for node in reversed(created):
            command("docker", "rm", "--force", "--volumes", node)
        if network_created:
            command("docker", "network", "rm", network)


if __name__ == "__main__":
    main()
