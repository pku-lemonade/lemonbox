#!/bin/bash
# Runs once under native guest systemd through cloud-init. No proxy variables.
set -euo pipefail
guest_user=$1
desktop=${2:-false}
docker=${3:-false}
guest_home=$(getent passwd "$guest_user" | cut -d: -f6)
install -d -m 0755 /var/log/journal
install -d -o "$guest_user" -g "$guest_user" -m 0755 "$guest_home/workspace"
# Install the release package set directly; Debian cloud images can omit the
# cloud-init apt_configure module and otherwise ignore a custom sources_list.
apt_snapshot=20261012T000000Z
sources=$(mktemp /etc/apt/sources.list.d/.debian.sources.XXXXXX)
trap 'rm -f "$sources"' EXIT
cat > "$sources" <<EOF
Types: deb
URIs: https://snapshot.debian.org/archive/debian/$apt_snapshot/
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no

Types: deb
URIs: https://snapshot.debian.org/archive/debian-security/$apt_snapshot/
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no
EOF
chmod 0644 "$sources"
mv -f "$sources" /etc/apt/sources.list.d/debian.sources
packages=(ca-certificates curl git sudo openssh-server locales python3 jq procps util-linux
          iproute2 iputils-ping bind9-dnsutils tmux libatomic1)
if [[ "$desktop" == true ]]; then
  packages+=(firefox-esr chromium xfce4 xfce4-terminal dbus-x11 xvfb x11vnc xauth
             x11-utils fonts-dejavu-core fonts-liberation)
fi
if [[ "$docker" == true ]]; then
  packages+=(docker.io docker-cli)
fi
apt-get update --error-on=any
DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends "${packages[@]}"
locale-gen en_US.UTF-8 >/dev/null
update-locale LANG=en_US.UTF-8
systemctl restart systemd-journald
systemctl enable --now ssh

runuser -u "$guest_user" -- env HOME="$guest_home" PATH="$guest_home/.local/bin:/usr/local/bin:/usr/bin:/bin" \
  bash -c '
    set -euo pipefail
    bootstrap=$(mktemp)
    trap '\''rm -f "$bootstrap"'\'' EXIT
    curl --fail --show-error --silent --location --proto =https --proto-redir =https \
      --retry 3 --retry-delay 2 --connect-timeout 20 --max-filesize 257068216 \
      https://downloads.claude.ai/claude-code-releases/2.1.296/linux-x64/claude -o "$bootstrap"
    printf "%s  %s\n" "24972e3bc859fab2b46ed4c1e51f7d6130f06d3bd550811a114640de3370d0de" "$bootstrap" \
      | sha256sum --check --status
    chmod 0700 "$bootstrap"
    "$bootstrap" install 2.1.296
    printf "%s  %s\n" "24972e3bc859fab2b46ed4c1e51f7d6130f06d3bd550811a114640de3370d0de" "$HOME/.local/bin/claude" \
      | sha256sum --check --status
    version=$("$HOME/.local/bin/claude" --version)
    [[ "$version" == "2.1.296 (Claude Code)" ]]
    printf "%s\n" "$version"
  '

if [[ "$desktop" == true ]]; then
  install -d -o "$guest_user" -g "$guest_user" -m 0755 "$guest_home/.local/share/applications"
  cat > "$guest_home/.local/share/applications/claude-code.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Claude Code
Comment=Run Claude Code
Exec=$guest_home/.local/bin/claude
Terminal=true
Icon=utilities-terminal
Categories=Development;
EOF
  chown "$guest_user:$guest_user" "$guest_home/.local/share/applications/claude-code.desktop"
  chmod 0644 "$guest_home/.local/share/applications/claude-code.desktop"
  install -m 0644 /usr/local/lib/lemon/firefox-privacy.js \
    /usr/lib/firefox-esr/defaults/pref/lemon-privacy.js
  cat > /etc/systemd/system/lemon-desktop.service <<EOF
[Unit]
Description=Linux desktop
After=network.target
[Service]
User=$guest_user
Group=$guest_user
Environment=HOME=$guest_home
Environment=DISPLAY=:0
Environment=XDG_RUNTIME_DIR=/run/lemon-desktop
RuntimeDirectory=lemon-desktop
RuntimeDirectoryMode=0700
ExecStart=/usr/local/lib/lemon/desktop.sh
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  # A headless server starts its optional desktop only when requested.
  for unit in lightdm.service avahi-daemon.socket avahi-daemon.service; do
    if systemctl cat "$unit" >/dev/null 2>&1; then
      systemctl disable --now "$unit"
    fi
  done
fi
if [[ "$docker" == true ]]; then
  usermod -aG docker "$guest_user"
  systemctl enable --now docker
  systemctl is-active --quiet docker
fi
systemctl is-active --quiet ssh
# The release snapshot controls only the initial package installation. Leave
# ordinary signed Debian repositories for the user's subsequent security updates.
sources=$(mktemp /etc/apt/sources.list.d/.debian.sources.XXXXXX)
trap 'rm -f "$sources"' EXIT
cat > "$sources" <<'EOF'
Types: deb
URIs: https://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: https://security.debian.org/debian-security
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
chmod 0644 "$sources"
mv -f "$sources" /etc/apt/sources.list.d/debian.sources
apt-get update --error-on=any
rm -f /usr/local/lib/lemon/provision.sh /usr/local/lib/lemon/firefox-privacy.js
