#!/usr/bin/env python3
"""Run kernel packet-loss rehearsal only in an owned local NATS network namespace."""
import json
import os
from pathlib import Path
import subprocess
import uuid


def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True, timeout=60).stdout.strip()


def main():
    run("sudo", "-n", "true")
    name = "identity-proxy-sync-tests-" + uuid.uuid4().hex[:8]
    image = "nats@sha256:b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927"
    created = False
    try:
        run("docker", "create", "--name", name, "--publish", "127.0.0.1::4222", image,
            "--auth", "identity-test-token")
        created = True
        run("docker", "start", name)
        pid = run("docker", "inspect", "--format", "{{.State.Pid}}", name)
        assert pid.isdigit() and int(pid) > 1
        endpoint = run("docker", "port", name, "4222/tcp")
        assert endpoint.startswith("127.0.0.1:")
        # Never modify the host network namespace or an external broker.
        assert os.readlink("/proc/self/ns/net") != run("sudo", "-n", "readlink", f"/proc/{pid}/ns/net")
        env = dict(os.environ, IDENTITY_TEST_NATS_CONTAINER=name,
                   IDENTITY_TEST_NATS_URL="nats://" + endpoint, IDENTITY_TEST_NATS_NETNS_PID=pid)
        subprocess.run(["dotnet", "test", "src/tests/Sufficit.Identity.Tests.csproj", "-c", "Release",
                        "--no-build", "--no-restore", "--filter", "FullyQualifiedName~Kernel_packet_loss",
                        "--nologo", "--logger", "console;verbosity=normal"], env=env,
                       cwd=Path(__file__).resolve().parent.parent, check=True, timeout=660)
        print(json.dumps({"image": image, "owned_container": name, "kernel_loss_test": "passed"}))
    finally:
        if created:
            run("docker", "rm", "--force", "--volumes", name)


if __name__ == "__main__":
    main()
