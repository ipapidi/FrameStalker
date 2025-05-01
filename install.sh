#!/bin/bash
echo "[*] Installing FrameStalker locally..."

# Install Python dependencies
pip install --upgrade pip
pip install PyQt5 scapy

INSTALL_DIR="$HOME/.local/share/Framestalker"
DESKTOP_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$DESKTOP_DIR/framestalker.desktop"
ICON_PATH="$INSTALL_DIR/assets/icon.png"
LAUNCH_PATH="$INSTALL_DIR/launch.sh"

# Create install dirs
mkdir -p "$INSTALL_DIR"
mkdir -p "$DESKTOP_DIR"

# Copy everything except install.sh and git files
rsync -av --exclude='install.sh' --exclude='.git' --exclude='.gitignore' ./ "$INSTALL_DIR"

# Create .desktop launcher with full launch path
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Name=Framestalker
Exec=bash -c "cd '$INSTALL_DIR' && sudo python3 -m ui.frame_stalker_gui"
Icon=$ICON_PATH
Terminal=true
Type=Application
Categories=Utility;Network;
EOF

chmod +x "$DESKTOP_FILE"

echo "[✓] Installed to $INSTALL_DIR"
echo "[✓] Launcher created at $DESKTOP_FILE"
echo "→ You may need to log out/in or run: update-desktop-database"

