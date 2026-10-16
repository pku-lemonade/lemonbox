"""Present the recovery state published by the gateway."""
import os
import subprocess


_READ_ERRORS = (OSError, ValueError, RuntimeError, subprocess.SubprocessError)


def route_alert(*, recovery=None, gateway_status='running', active=True):
    """Render reported phases without performing or inferring health checks."""
    if not active:
        return None
    recovery = recovery if isinstance(recovery, dict) else {}
    attempts = recovery.get('attempts', 0)
    if type(attempts) is not int or not 0 <= attempts <= 1000000:
        attempts = 0
    retrying = recovery.get('retrying') is True
    phase = recovery.get('status')
    if gateway_status == 'unavailable':
        reason = 'Gateway status is unavailable; the gateway could not be reached.'
        attempts, retrying = 0, False
    elif gateway_status != 'running':
        reason = 'The shared gateway is stopped; no route status is available.'
        attempts, retrying = 0, False
    elif phase in ('healthy', 'recovering'):
        return None
    elif phase == 'failed' and retrying:
        reason = 'Automatic recovery exhausted its fast retries; slower retries continue.'
    elif phase == 'failed':
        reason = 'Automatic recovery could not restore the fixed route; attention is required.'
    elif phase == 'blocked':
        reason = 'The fixed route is blocked and needs attention.'
        retrying = False
    else:
        reason = 'Gateway status is unavailable; its published recovery status could not be read.'
        retrying = False
    return {'status': 'active', 'reason': reason, 'attempts': attempts, 'retrying': retrying}


def gateway_alert(shared_gateway, *, active=True):
    """Read the published recovery report; all route detection stays in the gateway."""
    if not active:
        return None
    try:
        info = shared_gateway.info()
        if info is None:
            return route_alert(gateway_status='stopped')
        if not isinstance(info, dict) or not isinstance(info.get('State'), dict):
            return route_alert(gateway_status='unavailable')
        status = info['State'].get('Status')
        if status != 'running':
            return route_alert(gateway_status=status or 'unavailable')
    except _READ_ERRORS:
        return route_alert(gateway_status='unavailable')
    try:
        recovery = shared_gateway.recovery_status()
    except _READ_ERRORS:
        recovery = None
    return route_alert(recovery=recovery)


def owner_gateway_for_connection(connection):
    """Find a local owner's gateway only for an allocated loopback relay.

    SSH-only collaborators do not need Podman or a VM object. A local owner is
    recognized using the existing private, validated allocation registry.
    """
    invitation = connection.invitation
    if invitation.get('host') not in ('localhost', '127.0.0.1', '::1'):
        return None
    port = invitation.get('port')
    if type(port) is not int:
        return None
    # Lazy import keeps connection handling independent of VM runtime imports.
    from .gateway_runtime import SharedGateway, allocation_for
    try:
        gateway = SharedGateway()
        state = gateway.state
        if (state.is_symlink() or not state.is_dir() or state.stat().st_uid != os.getuid()
                or state.stat().st_mode & 0o077):
            return None
        path = gateway.allocations_path
        if not path.exists() or path.stat().st_size > 1048576:
            return None
        entries = gateway._registry()['profiles'].values()
        if any(allocation_for(entry['slot'])['ssh_port'] == port for entry in entries):
            return gateway
    except _READ_ERRORS:
        pass
    return None


def connection_alert(connection):
    """Expose local-owner alerts without probing a collaborator's backend."""
    gateway = owner_gateway_for_connection(connection)
    return gateway_alert(gateway) if gateway is not None else None
