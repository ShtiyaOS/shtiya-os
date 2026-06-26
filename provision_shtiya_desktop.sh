#!/bin/bash
# provision_shtiya_desktop.sh
# Expert DevOps Provisioning Script for Shtiya OS Desktop (Debian sid)
# Goal: Aggressive structural hardening for headless GNOME + Chrome Remote Desktop

set -e

# Logging function
log() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] $1"
}

# Check if running as root for specific sections
IS_ROOT=false
if [ "$EUID" -eq 0 ]; then
    IS_ROOT=true
fi

# Get the actual user if running with sudo
ACTUAL_USER="${SUDO_USER:-$USER}"
USER_HOME=$(eval echo "~$ACTUAL_USER")

################################################################################
# 1. Annihilate GNOME Tracker Subsystem (Run as Standard User context)
################################################################################
log "1. Annihilating GNOME Tracker Subsystem..."

# We need to run these as the actual user
run_as_user() {
    sudo -u "$ACTUAL_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$ACTUAL_USER")/bus" "$@"
}

# If we are root, we should mask services for the user specifically or globally
# The requirement says "systemctl --user mask", which should be done as the user.

# Attempting to stop/reset tracker as user
if command -v tracker3 >/dev/null 2>&1; then
    log "Resetting tracker3 filesystem..."
    sudo -u "$ACTUAL_USER" tracker3 reset --filesystem || true
fi

log "Removing tracker cache and data..."
sudo -u "$ACTUAL_USER" rm -rf "$USER_HOME/.cache/tracker" "$USER_HOME/.local/share/tracker"

log "Masking tracker user services..."
TRACKER_SERVICES=(
    tracker-store.service
    tracker-miner-fs.service
    tracker-miner-fs-3.service
    tracker-extract.service
    tracker-extract-3.service
    tracker-miner-apps.service
    tracker-writeback.service
    tracker-writeback-3.service
)

for svc in "${TRACKER_SERVICES[@]}"; do
    sudo -u "$ACTUAL_USER" XDG_RUNTIME_DIR="/run/user/$(id -u "$ACTUAL_USER")" systemctl --user mask "$svc" || true
done

log "Hiding tracker autostart entries..."
mkdir -p "$USER_HOME/.config/autostart"
for f in /etc/xdg/autostart/tracker-*.desktop; do
    if [ -f "$f" ]; then
        filename=$(basename "$f")
        cp "$f" "$USER_HOME/.config/autostart/"
        if ! grep -q "Hidden=true" "$USER_HOME/.config/autostart/$filename"; then
            echo "Hidden=true" >> "$USER_HOME/.config/autostart/$filename"
        fi
    fi
done
sudo chown -R "$ACTUAL_USER:$ACTUAL_USER" "$USER_HOME/.config/autostart"

################################################################################
# 2. Framebuffer Sovereignty (Disable GDM & Wayland) (Run as Root)
################################################################################
log "2. Enforcing Framebuffer Sovereignty..."
if [ "$IS_ROOT" = true ]; then
    log "Disabling GDM3..."
    systemctl stop gdm3 || true
    systemctl disable gdm3 || true

    log "Enforcing WaylandEnable=false..."
    for conf in /etc/gdm3/custom.conf /etc/gdm3/daemon.conf; do
        if [ -f "$conf" ]; then
            sed -i 's/^#\?WaylandEnable=true/WaylandEnable=false/' "$conf"
            if ! grep -q "^WaylandEnable=false" "$conf"; then
                sed -i '/\[daemon\]/a WaylandEnable=false' "$conf"
            fi
        fi
    done

    log "Creating CRD session for $ACTUAL_USER..."
    SESSION_FILE="$USER_HOME/.chrome-remote-desktop-session"
    echo "exec /etc/X11/Xsession /usr/bin/gnome-session" > "$SESSION_FILE"
    chmod +x "$SESSION_FILE"
    chown "$ACTUAL_USER:$ACTUAL_USER" "$SESSION_FILE"
else
    log "SKIPPING ROOT TASKS (GDM/Wayland): Not running as root."
fi

################################################################################
# 3. Patch Chrome Remote Desktop Python Daemon (Run as Root)
################################################################################
log "3. Patching Chrome Remote Desktop Daemon..."
if [ "$IS_ROOT" = true ]; then
    CRD_PATH="/opt/google/chrome-remote-desktop/chrome-remote-desktop"
    if [ -f "$CRD_PATH" ]; then
        log "Stopping CRD service..."
        systemctl stop chrome-remote-desktop@* || true

        if [ ! -f "${CRD_PATH}.orig" ]; then
            log "Backing up CRD daemon..."
            cp "$CRD_PATH" "${CRD_PATH}.orig"
        fi

        log "Applying patches via sed..."
        # Change FIRST_X_DISPLAY_NUMBER
        sed -i 's/FIRST_X_DISPLAY_NUMBER = 20/FIRST_X_DISPLAY_NUMBER = 0/' "$CRD_PATH"
        
        # Change DEFAULT_SIZES
        sed -i 's/DEFAULT_SIZES = "1600x1200,3840x2560"/DEFAULT_SIZES = "1920x1080,2560x1440,3840x2160"/' "$CRD_PATH"
        
        # Change DEFAULT_SIZE_NO_RANDR
        sed -i 's/DEFAULT_SIZE_NO_RANDR = "1600x1200"/DEFAULT_SIZE_NO_RANDR = "1920x1080"/' "$CRD_PATH"

        # Comment out the display lock check loop
        # We look for the specific while loop and comment it and the increment
        sed -i 's/^  while os.path.exists(X_LOCK_FILE_TEMPLATE % display):/# while os.path.exists(X_LOCK_FILE_TEMPLATE % display):/' "$CRD_PATH"
        sed -i 's/^    display += 1/#   display += 1/' "$CRD_PATH"
    else
        log "WARNING: Chrome Remote Desktop not found at $CRD_PATH"
    fi
else
    log "SKIPPING ROOT TASKS (CRD Patching): Not running as root."
fi

################################################################################
# 4. VirtualGL Injection (Run as Root)
################################################################################
log "4. Injecting VirtualGL..."
if [ "$IS_ROOT" = true ]; then
    log "Adding VirtualGL GPG key..."
    curl -fsSL https://packagecloud.io/dcommander/virtualgl/gpgkey | gpg --dearmor -o /etc/apt/trusted.gpg.d/VirtualGL.gpg || true

    log "Adding VirtualGL repository..."
    echo "deb https://packagecloud.io/dcommander/virtualgl/any/ any main" > /etc/apt/sources.list.d/virtualgl.list

    log "Installing VirtualGL..."
    apt-get update
    apt-get install -y virtualgl virtualgl32

    log "Configuring VirtualGL server..."
    /opt/VirtualGL/bin/vglserver_config -config +s +f -t

    log "Adding $ACTUAL_USER to vglusers group..."
    usermod -aG vglusers "$ACTUAL_USER"
else
    log "SKIPPING ROOT TASKS (VirtualGL): Not running as root."
fi

################################################################################
# 5. Persistent Identity Binding (Run as Mixed)
################################################################################
log "5. Binding Persistent Identity..."
if [ "$IS_ROOT" = true ]; then
    log "Adding $ACTUAL_USER to chrome-remote-desktop group..."
    usermod -aG chrome-remote-desktop "$ACTUAL_USER"

    log "Enabling and starting CRD service for $ACTUAL_USER..."
    systemctl enable "chrome-remote-desktop@$ACTUAL_USER.service"
    systemctl start "chrome-remote-desktop@$ACTUAL_USER.service"
else
    log "SKIPPING ROOT TASKS (Identity Binding): Not running as root."
fi

log "Provisioning complete for user: $ACTUAL_USER"
