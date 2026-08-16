#!/usr/bin/env python3
r"""
Generic .NET Application Deployment Script - PROJECT COPY (sufficit-identity)
Version: 202608160430
Revision: R018-identity - fork of R017 with Step 4d: carry excluded persistent FILES (appsettings*, certificate*.pfx) from live to staging before the atomic swap, in addition to folders
Last Modified UTC: 20260619163000
Central Repository: sufficit-project-management/scripts/dotnet/deploy.py

IMPORTANT: This is a COPY from the centralized version. To check if it is up to date,
compare the Revision number above with the central file in sufficit-project-management/scripts/dotnet/deploy.py.
Purpose: Deploy .NET applications directly from source with exclusions and progress tracking.
How it works: Loads `config.json`, resolves the project root relative to the script when local paths are not portable, optionally runs `dotnet publish` to a unique output folder, uploads the published files via SCP to a staging directory while the service keeps running, stops the service briefly for an atomic directory swap, restarts the service, and prints remote status/log information.
Usage: Run from the project root with `python3 deploy.py <server_name> --publish`; requires `config.json`, `dotnet`, SSH access to the target host, and the private key at `~/.ssh/id_ed25519_sufficit`.
Side-effects and required permissions: Publishes application binaries locally, copies files to the remote deployment folder, updates ownership/permissions remotely, restarts the target systemd service, and requires filesystem access plus SSH permission to the target server.

═══════════════════════════════════════════════════════════════════════════════
USAGE - HOW TO USE THIS SCRIPT
═══════════════════════════════════════════════════════════════════════════════

BASIC SYNTAX:
    python deploy.py <server_name> [--publish] [--hot] [--no-clean-binaries]

EXAMPLES:
    python deploy.py eveo-voip                # Staged deploy (default): upload to .staging, brief stop for swap
    python deploy.py eveo-voip --publish      # Publish into a unique timestamped folder, then staged deploy
    python deploy.py eveo-voip --hot          # Hot deploy: upload live dir, no stop, then restart (risky)
    python deploy.py eveo-voip --no-clean-binaries
    python deploy.py apoint-voip --publish
    python deploy.py google-voip

STAGED DEPLOY FLOW (default, minimum downtime):
    1. SCP upload → /opt/app.staging/       (service keeps running)
    2. systemctl stop                        ← downtime starts (~2-5s total)
    3. mv /opt/app → /opt/app.prev          (backup, instant)
    4. mv /opt/app.staging → /opt/app       (swap, instant)
    5. systemctl start                       ← downtime ends
    6. rm -rf /opt/app.prev                 (cleanup backup)
    Rollback if start fails: mv /opt/app.prev /opt/app && systemctl start <service>

JSON-ONLY CHANGE GUIDANCE:
    If the change set affects only already-deployed *.json files, prefer sending those
    files directly to the target folder instead of triggering a full publish + deploy.
    Use full deploy again when binaries, scripts, helpers, or any non-json runtime assets changed.

USAGE FROM PROJECT DIRECTORY:
  cd z:\Desenvolvimento\sufficit-asterisk-api
  python deploy.py eveo-voip

USAGE FROM CENTRAL SCRIPTS DIRECTORY:
  cd z:\Desenvolvimento\scripts\dotnet
  python deploy.py <project_name> <server_name>

REQUIREMENTS:
  1. Python 3.6+ installed
  2. SSH key at ~/.ssh/id_ed25519_sufficit configured
  3. config.json file in the same directory as deploy.py
  4. Publish folder already created (publish-net10.0 or publish-net7.0)
  5. Network access to target server on port 26492

CONFIG.JSON STRUCTURE:
  {
    "servers": [
      {"name": "eveo-voip", "dotnet": "net10.0"},
      {"name": "apoint-voip", "dotnet": "net10.0"},
      {"name": "google-voip", "dotnet": "net7.0"}
    ],
    "folder": "/opt/sufficit-asterisk-api",
    "systemd_service": "sufficit-asterisk-api.service",
    "deployment": {
      "excluded_folders": [],
      "auto_deploy": {
        "enabled": true,
        "skip_confirmation": true,
        "enabled_servers": ["eveo-voip", "apoint-voip"],
        "manual_only_servers": []
      },
      "publish_targets": [
        {"framework": "net7.0", "folder": "publish-net7.0"},
        {"framework": "net10.0", "folder": "publish-net10.0"}
      ]
    }
  }

WHAT THE SCRIPT DOES:
  1. Loads config from config.json
  2. Optionally runs dotnet publish into a unique timestamped folder
  3. Validates source publish directory exists
  4. Checks deployment policy (auto vs manual)
  5. [Staged] Uploads files via SCP to .staging directory while service runs
  6. [Staged] Stops service briefly for atomic directory swap
  7. Sets permissions on helper scripts
  8. Changes ownership to dotnetuser
  9. Restarts systemd service
  10. Displays service status and recent logs
  11. [Staged] Removes backup directory after successful start

DEPLOYMENT FLOW (staged, default):
    ✅ Optional unique publish folder per --publish run
    ✅ Verify source directory
    ✅ Check deployment policy
    ✅ Prepare .staging directory on remote
    ✅ Upload files via SCP to .staging (service running during this step)
    ✅ Configure permissions on .staging
    ✅ Stop service (brief window starts here)
    ✅ Atomic swap: live → .prev, staging → live
    ✅ Start service (brief window ends)
    ✅ Show status
    ✅ Display logs
    ✅ Remove .prev backup

TROUBLESHOOTING:
  - "Source directory not found": Run publish command first or check path
    - "DLL locked during publish": Use --publish so the script generates a fresh timestamped folder
    - "Only appsettings or other *.json changed": Prefer direct upload of the changed json files to the target path
  - "Connection timed out": Check server hostname and network connectivity
  - "Permission denied": Verify SSH key is configured correctly
  - Service fails to start: Check logs with journalctl

═══════════════════════════════════════════════════════════════════════════════

IMPORTANT: This is a PROJECT COPY of the centralized deployment script.
The master copy lives in sufficit-project-management/scripts/dotnet/deploy.py.

INSTRUCTIONS FOR MAINTENANCE:
- Do NOT make local-only changes here; edit the central master copy first.
- After updating the central copy, re-copy it here and re-apply the PROJECT COPY header.
- To check if this file is up to date, compare the Revision number above with the central file.
- Revision format: R### - Brief description of changes
"""

import os
import sys
import subprocess
import time
import json
from datetime import datetime
from pathlib import Path

# SSH options shared across all ssh/scp calls.
# ServerAliveInterval + ServerAliveCountMax: kill the connection if the remote
#   stops responding (prevents the deploy script from blocking the calling shell/chat session).
# ConnectTimeout: fail fast on unreachable hosts instead of waiting indefinitely.
_SSH_OPTS = (
    "-o StrictHostKeyChecking=no "
    "-o ServerAliveInterval=10 "
    "-o ServerAliveCountMax=3 "
    "-o ConnectTimeout=15"
)

def load_config():
    """Load configuration from config.json"""
    config_path = Path(__file__).parent / "config.json"
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def print_header(title):
    print("=" * 60)
    print(f"   {title}")
    print("=" * 60)
    print()

def safe_print(message):
    try:
        print(message)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or 'utf-8'
        sanitized = message.encode(encoding, errors='replace').decode(encoding, errors='replace')
        print(sanitized)

def print_progress(message, emoji="🔄"):
    safe_print(f"{emoji} {message}")

def run_command_with_progress(cmd, description):
    """Execute command with real-time output"""
    print_progress(f"{description}...")
    safe_print(f"💻 Command: {cmd}")
    safe_print("-" * 50)

    try:
        # Use subprocess.Popen for real-time output
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding='utf-8',
            errors='replace',
            bufsize=1
        )

        # Print output in real-time
        for line in process.stdout:
            safe_print(line.rstrip())

        # Wait for completion
        return_code = process.wait()

        if return_code == 0:
            print_progress("Command completed successfully!", "✅")
            return True
        else:
            print_progress(f"Command failed with return code {return_code}", "❌")
            return False

    except Exception as e:
        print_progress(f"Error executing command: {e}", "❌")
        return False

def resolve_project_root(config):
    """Resolve the local project root, preferring config when it points to a valid existing path."""
    configured_local = config.get("folders", {}).get("local")
    if configured_local:
        configured_path = Path(os.path.expandvars(os.path.expanduser(configured_local)))
        if configured_path.exists():
            return configured_path

    return Path(__file__).parent


def get_ssh_key_path():
    """Resolve the SSH key path portably across Linux/Windows style environments."""
    return str(Path.home() / ".ssh" / "id_ed25519_sufficit")


def _get_remote_path(config):
    """Return the primary remote deployment path from config."""
    return config.get("folders", {}).get("remote") or config.get("folder")

def _get_staging_path(config):
    """Return the staging directory path (sibling of the live dir with .staging suffix)."""
    return _get_remote_path(config) + ".staging"

def _get_backup_path(config):
    """Return the backup directory path kept after an atomic swap (.prev suffix)."""
    return _get_remote_path(config) + ".prev"

def build_scp_command(config, server_name, source_path, target_path=None):
    """Build SCP command copying source_path/* to target_path (defaults to live remote dir)."""
    if target_path is None:
        target_path = _get_remote_path(config)
    ssh_key = get_ssh_key_path()
    ssh_port = "26492"
    return f'scp -4 -i "{ssh_key}" -P {ssh_port} {_SSH_OPTS} -r "{source_path}"/* root@{server_name}.sufficit.com.br:{target_path}/'

def copy_with_exclusions_info(config, source_path):
    """Show what folders exist but will be preserved on server"""
    excluded = config["deployment"].get("excluded_folders", [])

    print_progress("Analyzing source directory...", "🔍")

    total_items = 0
    excluded_from_source = 0

    if os.path.exists(source_path):
        for item in os.listdir(source_path):
            total_items += 1
            if item in excluded:
                excluded_from_source += 1
                print_progress(f"Not in source (will be carried from live to staging before swap): {item}", "💾")

        print_progress(f"Total items in source: {total_items}, Will preserve on server: {excluded_from_source}", "📊")

    return total_items, excluded_from_source

def check_deployment_policy(config, server_name):
    """Check deployment policy for the specified server"""
    # Check if auto_deploy configuration exists
    auto_deploy_config = config.get("deployment", {}).get("auto_deploy", {})

    # If auto_deploy is enabled and skip_confirmation is true, proceed without asking
    if auto_deploy_config.get("enabled") and auto_deploy_config.get("skip_confirmation"):
        print_progress(f"✅ {server_name} - Auto deploy enabled (skip confirmation)", "🚀")
        return True

    # If auto_deploy config doesn't exist or is disabled, use the old policy-based system
    if not auto_deploy_config or not auto_deploy_config.get("enabled"):
        # Check if the old policy system exists
        auto_deploy_servers = auto_deploy_config.get("enabled_servers", [])
        manual_only_servers = auto_deploy_config.get("manual_only_servers", [])

        if server_name in auto_deploy_servers:
            print_progress(f"✅ {server_name} - Auto deploy enabled", "🚀")
            return True
        elif server_name in manual_only_servers:
            print_progress(f"⚠️  {server_name} - Deploy only on user request", "⚠️")
            print_progress("Policy: Auto deploy only on main server (apoint-apps)", "📋")
            response = input(f"Do you want to continue with manual deploy to {server_name}? (y/n): ").lower().strip()
            if response in ['y', 'yes']:
                print_progress("Continuing with manual deploy...", "✅")
                return True
            else:
                print_progress("Deploy cancelled by user", "❌")
                return False

    # If skip_confirmation is false or not set, ask for confirmation
    response = input(f"Deploy to {server_name}? (y/n): ").lower().strip()
    if response in ['y', 'yes']:
        print_progress("Continuing with deploy...", "✅")
        return True
    else:
        print_progress("Deploy cancelled by user", "❌")
        return False

def build_ssh_command(server_name, remote_command, timeout_seconds=None):
    """Build SSH command.

    timeout_seconds wraps the remote command with `timeout <N>` so that status
    or log commands (journalctl, systemctl status) cannot hang the local process
    when the SSH connection stalls after the command exits on the remote side.
    """
    ssh_key = get_ssh_key_path()
    ssh_port = "26492"
    if timeout_seconds:
        remote_command = f"timeout {timeout_seconds} {remote_command}"
    return f'ssh -i "{ssh_key}" -p {ssh_port} {_SSH_OPTS} root@{server_name}.sufficit.com.br "{remote_command}"'

def fix_helpers_permissions(config, server_name, target_path=None):
    """Fix permissions for helpers scripts after copying.

    target_path defaults to the live remote directory; pass the staging path
    when calling this before an atomic swap so permissions are correct at swap time.
    """
    print_progress("Configuring helpers permissions and ownership...", "🔧")

    if target_path is None:
        target_path = _get_remote_path(config)

    commands = [
        f"chmod +x {target_path}/helpers/*.sh 2>/dev/null || true",
        f"chown dotnetuser:dotnetuser -R {target_path}/",
    ]

    # Syslog symlink is installed from the live dir, not the staging dir, so only
    # run these commands when operating on the live directory.
    live_path = _get_remote_path(config)
    if 'syslog' in config and target_path == live_path:
        commands.extend([
            f"ln -f {target_path}/{config['syslog']['config_file']} {config['syslog']['rsyslog_target']}",
            f"chmod {config['syslog']['permissions']} {config['syslog']['rsyslog_target']}",
            "systemctl restart rsyslog"
        ])

    for cmd in commands:
        ssh_cmd = build_ssh_command(server_name, cmd)
        run_command_with_progress(ssh_cmd, f"Executing: {cmd}")

    print_progress("✅ Helpers permissions configured", "✅")

def cleanup_remote_binaries(config, server_name, target_path=None):
    """Remove only DLL/PDB files from a remote directory before upload."""
    if target_path is None:
        target_path = _get_remote_path(config)
    cleanup_script = (
        f"cd {target_path} || exit 1; "
        "find . -maxdepth 1 -type f \\( "
        "-iname '*.dll' -o -iname '*.pdb' "
        "\\) -print -delete"
    )
    ssh_cmd = build_ssh_command(server_name, cleanup_script)
    return run_command_with_progress(ssh_cmd, f"Cleaning remote DLL/PDB files on {server_name}")

def ensure_remote_target_directory(config, server_name):
    """Ensure the remote deployment target directory exists before cleanup/upload."""
    target_path = _get_remote_path(config)
    mkdir_cmd = build_ssh_command(server_name, f"mkdir -p {target_path}")
    return run_command_with_progress(mkdir_cmd, f"Ensuring remote target directory on {server_name}")

def ensure_staging_directory(config, server_name):
    """Create (or clear) the .staging directory on the remote host before upload."""
    staging_path = _get_staging_path(config)
    # Remove any leftover staging from a previous failed deploy, then recreate.
    cmd = f"rm -rf {staging_path} && mkdir -p {staging_path}"
    ssh_cmd = build_ssh_command(server_name, cmd)
    return run_command_with_progress(ssh_cmd, f"Preparing staging directory on {server_name}")

def atomic_swap_with_backup(config, server_name):
    """Atomically replace the live directory with .staging, keeping the old dir as .prev.

    Sequence (all-or-nothing with shell &&):
        rm -rf .prev                   -- discard any previous backup
        mv live → .prev                -- back up current live
        mv .staging → live             -- promote staging to live

    If the second mv fails, .prev still holds the last good version and the
    admin can recover manually: mv .prev live && systemctl start <service>
    """
    live_path = _get_remote_path(config)
    staging_path = _get_staging_path(config)
    backup_path = _get_backup_path(config)

    swap_script = (
        f"rm -rf {backup_path} && "
        f"mv {live_path} {backup_path} && "
        f"mv {staging_path} {live_path}"
    )
    ssh_cmd = build_ssh_command(server_name, swap_script)
    return run_command_with_progress(ssh_cmd, f"Atomic swap staging → live on {server_name}")

def cleanup_backup_directory(config, server_name):
    """Remove the .prev backup directory after a successful service start."""
    backup_path = _get_backup_path(config)
    ssh_cmd = build_ssh_command(server_name, f"rm -rf {backup_path}")
    return run_command_with_progress(ssh_cmd, f"Removing backup directory on {server_name}")

def remote_service_exists(config, server_name):
    """Check whether the configured systemd unit already exists on the remote host."""
    service_name = config["systemd_service"]
    exists_cmd = build_ssh_command(
        server_name,
        f"systemctl list-unit-files {service_name} --no-legend --no-pager | grep -Fq '{service_name}'"
    )
    result = subprocess.run(exists_cmd, shell=True)
    return result.returncode == 0

def remote_install_helper_exists(config, server_name):
    """Check whether the project shipped an install helper to bootstrap the remote service."""
    target_path = config.get("folders", {}).get("remote") or config.get("folder")
    helper_cmd = build_ssh_command(server_name, f"test -f {target_path}/helpers/install.sh")
    result = subprocess.run(helper_cmd, shell=True)
    return result.returncode == 0

def run_remote_install_helper(config, server_name):
    """Execute the install helper on the remote host to provision systemd/syslog artifacts."""
    target_path = config.get("folders", {}).get("remote") or config.get("folder")
    install_cmd = build_ssh_command(server_name, f"bash {target_path}/helpers/install.sh")
    return run_command_with_progress(install_cmd, f"Running first-install helper on {server_name}")

def run_systemd_daemon_reload(server_name):
    """Reload systemd units so updated service files are applied before restart."""
    reload_cmd = build_ssh_command(server_name, "systemctl daemon-reload")
    return run_command_with_progress(reload_cmd, f"Reloading systemd units on {server_name}")

def get_main_assembly_name(config, source_path):
    """Resolve the main entry-point DLL name (e.g. Sufficit.EndPoints.dll).

    Derives the assembly base name from the configured project_file and verifies the
    corresponding DLL actually exists in the published source folder before deploying.
    Falls back to None when the name cannot be determined so callers can skip the check.
    """
    project_file = config.get("project_file")
    if not project_file:
        return None

    base_name = os.path.splitext(os.path.basename(project_file))[0]
    main_dll = f"{base_name}.dll"

    # Only treat it as the main DLL if the publish folder actually contains it.
    if os.path.isfile(os.path.join(source_path, main_dll)):
        return main_dll

    return None


def count_local_dlls(source_path):
    """Count top-level *.dll files in the published source folder."""
    try:
        return sum(
            1 for entry in os.listdir(source_path)
            if entry.lower().endswith(".dll") and os.path.isfile(os.path.join(source_path, entry))
        )
    except OSError:
        return 0


def verify_remote_upload(config, server_name, source_path, target_path):
    """Verify the SCP upload landed completely before swapping/restarting.

    Partial SCP transfers can drop files silently (including the main entry DLL),
    which leaves systemd failing with 'dotnet-<App>.dll does not exist'. This guard
    confirms the main DLL is present at target_path and that the remote top-level DLL
    count matches the local publish folder, aborting before an atomic swap (staged)
    or a restart (hot) so a broken upload never reaches the live service.

    target_path is the directory just uploaded to: the .staging dir in staged mode,
    or the live remote dir in hot mode.
    """
    main_dll = get_main_assembly_name(config, source_path)
    local_dll_count = count_local_dlls(source_path)

    print_progress("Verifying remote upload integrity...", "🔎")

    # Confirm the main entry DLL exists remotely (the most critical file).
    if main_dll:
        check_main_cmd = build_ssh_command(
            server_name,
            f"test -f {target_path}/{main_dll}",
            timeout_seconds=15
        )
        result = subprocess.run(check_main_cmd, shell=True)
        if result.returncode != 0:
            print_progress(
                f"Main assembly {main_dll} is MISSING at {target_path} on {server_name} after upload - aborting",
                "❌"
            )
            return False
        print_progress(f"Main assembly present on remote: {main_dll}", "✅")

    # Compare remote vs local top-level DLL counts to catch partial transfers.
    count_cmd = build_ssh_command(
        server_name,
        f"ls -1 {target_path}/*.dll 2>/dev/null | wc -l",
        timeout_seconds=15
    )
    proc = subprocess.run(count_cmd, shell=True, capture_output=True, text=True)
    remote_dll_count = 0
    if proc.returncode == 0:
        try:
            remote_dll_count = int(proc.stdout.strip())
        except ValueError:
            remote_dll_count = 0

    print_progress(
        f"DLL count - local: {local_dll_count}, remote: {remote_dll_count}",
        "📊"
    )

    if local_dll_count > 0 and remote_dll_count < local_dll_count:
        print_progress(
            f"Remote DLL count ({remote_dll_count}) is lower than local ({local_dll_count}) - "
            "upload appears incomplete, aborting before swap/restart",
            "❌"
        )
        return False

    print_progress("Remote upload verified - file counts consistent", "✅")
    return True


def deploy_to_server(config, server_name, source_path, hot=False, clean_binaries=True):
    """Deploy to server using the staged flow by default (minimum downtime).

    Staged flow (hot=False, default):
        1. Upload to .staging while service runs  — no downtime here
        2. Stop service                           — brief downtime window starts
        3. Atomic swap: live → .prev, staging → live
        4. Start service                          — brief downtime window ends
        5. Remove .prev backup

    Hot flow (hot=True):
        Upload directly to live dir while service runs, then restart.
        Faster but risks DLL-in-use errors on Windows; fine on Linux with .so/.dll.
    """
    print_header(f"DEPLOYING TO {server_name.upper()}")

    target_path = _get_remote_path(config)
    staging_path = _get_staging_path(config)

    print_progress(f"Target Server: {server_name}", "🎯")
    print_progress(f"Source: {source_path}", "📂")
    print_progress(f"Target: {target_path}", "📁")
    print_progress(f"Mode: {'hot (upload live, restart)' if hot else 'staged (upload .staging, atomic swap)'}", "⚡")
    print_progress(f"Remote DLL/PDB cleanup: {'enabled' if clean_binaries else 'disabled'}", "🧹")
    print()

    service_exists = remote_service_exists(config, server_name)
    first_install = not service_exists
    if first_install:
        print_progress(
            f"Service {config['systemd_service']} is not installed yet on {server_name} - enabling first-install mode",
            "🆕"
        )
    else:
        print_progress(f"Service {config['systemd_service']} already exists on {server_name}", "✅")
    print()

    if not ensure_remote_target_directory(config, server_name):
        return False
    print()

    total_items, excluded_items = copy_with_exclusions_info(config, source_path)
    print()

    # ── STAGED FLOW ────────────────────────────────────────────────────────────
    if not hot:
        # Step 1: Prepare .staging directory (remove stale, recreate)
        if not ensure_staging_directory(config, server_name):
            return False
        print()

        # Step 2: Optionally clean DLL/PDB files in the staging directory
        if clean_binaries:
            if not cleanup_remote_binaries(config, server_name, target_path=staging_path):
                return False
            print()

        # Step 3: Upload to .staging while service is still running
        scp_cmd = build_scp_command(config, server_name, source_path, target_path=staging_path)
        print_progress("ℹ️  Uploading to .staging — service remains running during transfer", "ℹ️")
        if not run_command_with_progress(scp_cmd, f"Uploading files to {server_name} staging"):
            return False
        print()

        # Step 4: Fix permissions on staging before the swap
        fix_helpers_permissions(config, server_name, target_path=staging_path)
        print()

        # Step 4b: Verify the staging upload landed completely BEFORE any downtime.
        # Aborting here keeps the live service untouched (zero downtime on failure).
        if not verify_remote_upload(config, server_name, source_path, staging_path):
            print_progress(
                f"Staging upload verification failed for {server_name} - swap NOT performed, "
                "live service untouched. Re-run the deploy or inspect the network/SCP transfer.",
                "🛑"
            )
            return False
        print()

        # Step 4c: Copy excluded (persistent) folders from live into staging before swap.
        # The atomic swap replaces live with staging entirely; folders absent from the
        # published output (App_Arquivos, App_Temp, .whisper, Extra) must be carried over
        # so they are not lost when the old live dir becomes .prev and is later deleted.
        excluded_folders = config["deployment"].get("excluded_folders", [])
        excluded_files = config["deployment"].get("excluded_files", [])
        live_path = _get_remote_path(config)
        carry_cmds = " ; ".join(
            f"[ -d {live_path}/{f} ] && cp -a {live_path}/{f} {staging_path}/ || true"
            for f in excluded_folders
        ) + " ; " + " ; ".join(
            f"[ -f {live_path}/{name} ] && cp -a -p {live_path}/{name} {staging_path}/ || true"
            for name in excluded_files
        )
        if excluded_folders or excluded_files:
            carry_cmd = build_ssh_command(server_name, carry_cmds)
            run_command_with_progress(carry_cmd, f"Carrying persistent folders/files to staging on {server_name}")
            print()

        # Step 5: Stop service — downtime window starts here
        if service_exists:
            stop_cmd = build_ssh_command(server_name, f"systemctl stop {config['systemd_service']}")
            if not run_command_with_progress(stop_cmd, f"Stopping service on {server_name}"):
                return False
            print()

        # Step 6: Atomic swap (instant — just renames on the same filesystem)
        if not atomic_swap_with_backup(config, server_name):
            print_progress(
                f"Swap failed — backup preserved at {_get_backup_path(config)}; "
                "start the old version manually: "
                f"mv {_get_backup_path(config)} {target_path} && systemctl start {config['systemd_service']}",
                "❌"
            )
            return False
        print()

        # Step 7: Apply syslog symlink from live dir now that swap is done
        if 'syslog' in config and service_exists:
            fix_helpers_permissions(config, server_name, target_path=target_path)
            print()

    # ── HOT FLOW ───────────────────────────────────────────────────────────────
    else:
        if clean_binaries:
            if not cleanup_remote_binaries(config, server_name, target_path=target_path):
                return False
            print()

        scp_cmd = build_scp_command(config, server_name, source_path, target_path=target_path)
        print_progress("ℹ️  Hot deploy: uploading directly to live directory while service runs", "ℹ️")
        if not run_command_with_progress(scp_cmd, f"Uploading files to {server_name}"):
            return False
        print()

        # Verify the live upload landed completely before restarting the service.
        if not verify_remote_upload(config, server_name, source_path, target_path):
            print_progress(
                f"Hot upload verification failed for {server_name} - service NOT restarted. "
                "Re-run the deploy or inspect the network/SCP transfer.",
                "🛑"
            )
            return False
        print()

        fix_helpers_permissions(config, server_name, target_path=target_path)
        print()

    print_progress("✅ Server-specific folders preserved (not overwritten)", "💾")
    print()

    # ── FIRST INSTALL BOOTSTRAP ────────────────────────────────────────────────
    if first_install:
        if not remote_install_helper_exists(config, server_name):
            print_progress("Install helper not found on remote host - cannot bootstrap first deployment", "❌")
            return False
        if not run_remote_install_helper(config, server_name):
            return False
        print()

    # ── RESTART SERVICE ────────────────────────────────────────────────────────
    if not first_install:
        if not run_systemd_daemon_reload(server_name):
            return False
        print()

        restart_cmd = build_ssh_command(server_name, f"systemctl restart {config['systemd_service']}")
        if not run_command_with_progress(restart_cmd, f"Restarting service on {server_name}"):
            return False
        print()

    # ── STATUS AND LOGS ────────────────────────────────────────────────────────
    # Wrap both commands with `timeout` so a stale SSH connection cannot block
    # the local shell/chat session after the remote command has already exited.
    status_cmd = build_ssh_command(
        server_name,
        f"systemctl status {config['systemd_service']} --no-pager",
        timeout_seconds=15
    )
    run_command_with_progress(status_cmd, f"Checking service status on {server_name}")
    print()

    print_progress("Checking service logs...", "📋")
    logs_cmd = build_ssh_command(
        server_name,
        f"journalctl -u {config['systemd_service']} -n 10 --no-pager",
        timeout_seconds=15
    )
    run_command_with_progress(logs_cmd, f"Checking recent logs on {server_name}")
    print()

    # ── CLEANUP BACKUP ─────────────────────────────────────────────────────────
    if not hot and service_exists:
        cleanup_backup_directory(config, server_name)
        print()

    print_progress(f"{server_name} deployment successful!", "🎉")
    print_progress(f"Service: {config['systemd_service']} is running", "⚙️")
    return True

def get_server_names(config):
    """Extract server names from config.json regardless of structure"""
    if isinstance(config['servers'], list):
        if len(config['servers']) > 0 and isinstance(config['servers'][0], dict):
            # Structure: [{"name": "server", "dotnet": "net10.0"}, ...]
            return [server['name'] for server in config['servers']]
        else:
            # Structure: ["server1", "server2", ...]
            return config['servers']
    return []

def get_dotnet_version(config, server_name):
    """Get dotnet version for the specified server"""
    for server in config['servers']:
        if isinstance(server, dict):
            if server.get('name') == server_name:
                return server.get('dotnet', 'net10.0')
        elif server == server_name:
            return 'net10.0'
    return 'net10.0'  # fallback

def get_publish_output_folder(base_publish_folder):
    """Create a unique publish folder for the current deployment run."""
    base_folder = Path(base_publish_folder)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return str(base_folder.parent / f"{base_folder.name}-{timestamp}")


def run_dotnet_publish(config, publish_folder):
    """Run dotnet publish to prepare the publish folder before deploying.
    Discovers the .csproj from config.json 'project_file' field or auto-scans src/."""
    project_root = resolve_project_root(config)

    project_file = config.get("project_file")
    if project_file:
        project_path = project_root / project_file
    else:
        src_dir = project_root / "src"
        if src_dir.exists():
            csproj_files = list(src_dir.glob("*.csproj"))
            if not csproj_files:
                print_progress("No .csproj found in src/ folder", "❌")
                return False
            project_path = csproj_files[0]
        else:
            print_progress("src/ folder not found and no project_file in config.json", "❌")
            return False

    if not project_path.exists():
        print_progress(f"Project file not found: {project_path}", "❌")
        return None

    output_folder = get_publish_output_folder(publish_folder)
    print_progress(f"Publishing: {project_path.name} → {publish_folder}", "🔨")
    cmd = f'dotnet publish "{project_path}" -c Release --output "{output_folder}" /consoleloggerparameters:NoSummary'

    if run_command_with_progress(cmd, "dotnet publish"):
        return output_folder

    return None


def get_publish_folder(config, server_name):
    """Get publish folder for the specified server.
    Priority: deployment.source_folder > simple publish/ > publish_targets > publish-{framework}"""
    project_root = resolve_project_root(config)

    deployment_config = config.get("deployment", {})
    configured_source = deployment_config.get("source_folder")
    if configured_source:
        source_path = Path(os.path.expandvars(os.path.expanduser(configured_source)))
        if not source_path.is_absolute():
            source_path = project_root / source_path
        print_progress(f"Using configured source folder: {source_path}", "📁")
        return str(source_path)

    # Simple publish/ folder (single-target apps)
    simple_publish = project_root / "publish"
    if simple_publish.exists() and simple_publish.is_dir():
        print_progress("Found simple 'publish' folder - using single-target deployment", "📁")
        return str(simple_publish)

    # Framework-based publish_targets
    dotnet_version = get_dotnet_version(config, server_name)
    if 'publish_targets' in deployment_config:
        for target in deployment_config['publish_targets']:
            if target['framework'] == dotnet_version:
                return str(project_root / target['folder'])

    # Fallback to default naming
    return str(project_root / f"publish-{dotnet_version}")

def get_expected_runtime_filenames(config, source_path):
    """Collect runtime filenames declared by the app deps graph for validation."""
    deps_files = sorted(Path(source_path).glob("*.deps.json"))
    if not deps_files:
        return set()

    try:
        with open(deps_files[0], 'r', encoding='utf-8') as f:
            deps = json.load(f)
    except Exception as e:
        print_progress(f"Unable to inspect deps graph from {deps_files[0].name}: {e}", "⚠️")
        return set()

    runtime_target_name = deps.get("runtimeTarget", {}).get("name")
    targets = deps.get("targets", {})
    if not runtime_target_name or runtime_target_name not in targets:
        runtime_target_name = next(iter(targets), None)
    if not runtime_target_name:
        return set()

    expected = set()
    for library in targets.get(runtime_target_name, {}).values():
        for section_name in ("runtime", "native", "runtimeTargets"):
            section = library.get(section_name, {})
            for relative_path in section.keys():
                expected.add(Path(relative_path).name)

    project_file = config.get("project_file")
    if project_file:
        project_name = Path(project_file).stem
        expected.update({
            f"{project_name}.dll",
            f"{project_name}.exe",
            f"{project_name}.deps.json",
            f"{project_name}.runtimeconfig.json",
        })

    return expected

def validate_source_directory(config, source_path, run_publish):
    """Reject stale simple publish folders that contain DLLs outside the deps graph."""
    expected = get_expected_runtime_filenames(config, source_path)
    if not expected:
        return True

    allowed_orphans = set(config.get("deployment", {}).get("allowed_orphan_dlls", []))
    actual_dlls = {path.name for path in Path(source_path).glob("*.dll")}
    orphan_dlls = sorted(name for name in actual_dlls if name not in expected and name not in allowed_orphans)

    if not orphan_dlls:
        return True

    print_progress("Detected DLLs in the source directory that are not declared in the publish deps graph:", "⚠️")
    for name in orphan_dlls:
        safe_print(f"   - {name}")

    if Path(source_path).name.lower() == "publish" and not run_publish:
        print_progress("Refusing deploy from stale reusable 'publish' folder. Run with --publish or rebuild the publish folder first.", "❌")
        return False

    print_progress("Continuing because the source folder is not the reusable simple 'publish' folder or --publish was used.", "ℹ️")
    return True

def main():
    args = sys.argv[1:]
    run_publish = "--publish" in args
    hot = "--hot" in args
    clean_binaries = "--no-clean-binaries" not in args
    args = [a for a in args if a != "--publish"]
    args = [a for a in args if a != "--hot"]
    args = [a for a in args if a != "--no-clean-binaries"]

    if not args:
        config = load_config()
        print("Usage: python deploy.py <server_name> [--publish] [--hot] [--no-clean-binaries]")
        server_names = get_server_names(config)
        print(f"Available servers: {', '.join(server_names)}")
        print("Options:")
        print("  --publish                 Run dotnet publish before deploy")
        print("  --hot                     Upload live dir while running, then restart (skips staged flow)")
        print("  --no-clean-binaries       Skip default cleanup of remote DLL/PDB files")
        sys.exit(1)

    server = args[0]
    config = load_config()

    server_names = get_server_names(config)
    if server not in server_names:
        print_progress(f"Invalid server: {server}", "❌")
        print(f"Available servers: {', '.join(server_names)}")
        sys.exit(1)

    print_header("GENERIC .NET APPLICATION DEPLOYMENT")
    print_progress(f"Service: {config['systemd_service']}", "⚙️")
    print_progress(f"Deployment script location: {__file__}", "📍")
    print_progress("Generic script - configure via config.json", "🔧")
    print()

    publish_folder = get_publish_folder(config, server)

    # --publish: run dotnet publish before deploying
    if run_publish:
        published_output = run_dotnet_publish(config, publish_folder)
        if not published_output:
            print_progress("dotnet publish failed - aborting deploy", "❌")
            sys.exit(1)
        publish_folder = published_output
        print()

    source_path = Path(publish_folder)
    if not source_path.exists():
        print_progress(f"Source directory not found: {source_path}", "❌")
        sys.exit(1)

    if not validate_source_directory(config, source_path, run_publish):
        sys.exit(1)

    print_progress(f"Source directory verified: {source_path}", "✅")
    print()

    # Check deployment policy
    if not check_deployment_policy(config, server):
        print_progress("Deploy cancelled due to policy restrictions", "❌")
        sys.exit(1)

    print()

    # Deploy to server
    success = deploy_to_server(config, server, source_path, hot=hot, clean_binaries=clean_binaries)

    if success:
        print_header("DEPLOYMENT COMPLETED SUCCESSFULLY")
        print_progress(f"{server} is now running the updated version", "🚀")
        print_progress("Application is active and ready for use!", "✨")
    else:
        print_header("DEPLOYMENT COMPLETED WITH ISSUES")
        print_progress(f"Check {server} manually for any issues", "🔧")
        sys.exit(1)

if __name__ == "__main__":
    main()
