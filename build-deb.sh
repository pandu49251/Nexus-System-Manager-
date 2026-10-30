#!/bin/sh
#
# Build the Nexus System Doctor .deb package.
#
# The package installs into /opt/nexus-system-doctor (self-contained, so it
# can never conflict with a distribution Python package), drops a launcher in
# /usr/bin, a menu entry, an icon, and the polkit policy that lets the GUI ask
# for administrator rights through pkexec.
#
# Usage:  packaging/build-deb.sh [output-directory]
#
set -eu

SRC=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SRC/nexus_doctor/version.py")
OUT=${1:-"$SRC/dist"}
STAGE="$OUT/.stage-nexus-system-doctor"
PKG="$OUT/nexus-system-doctor_${VERSION}_all.deb"

APPDIR="$STAGE/opt/nexus-system-doctor"
HELPERDIR="$STAGE/usr/lib/nexus-system-doctor"

echo "Building Nexus System Doctor $VERSION"
echo "  source: $SRC"
echo "  output: $PKG"

rm -rf "$STAGE"
mkdir -p "$OUT" "$APPDIR" "$HELPERDIR"
mkdir -p "$STAGE/usr/bin" "$STAGE/usr/share/applications"
mkdir -p "$STAGE/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$STAGE/usr/share/polkit-1/actions"
mkdir -p "$STAGE/usr/share/doc/nexus-system-doctor/screenshots"

# --- application ---------------------------------------------------------
cp -a "$SRC/nexus_doctor" "$APPDIR/"
install -m 0755 "$SRC/nexus-doctor" "$APPDIR/nexus-doctor"
ln -sf /opt/nexus-system-doctor/nexus-doctor "$STAGE/usr/bin/nexus-doctor"

# --- privileged helper + policy -----------------------------------------
install -m 0755 "$SRC/share/privileged-helper" "$HELPERDIR/privileged-helper"
install -m 0644 "$SRC/share/org.nexus.system-doctor.policy" \
    "$STAGE/usr/share/polkit-1/actions/org.nexus.system-doctor.policy"

# --- desktop integration -------------------------------------------------
install -m 0644 "$SRC/share/nexus-system-doctor.desktop" \
    "$STAGE/usr/share/applications/nexus-system-doctor.desktop"
install -m 0644 "$SRC/share/nexus-system-doctor.svg" \
    "$STAGE/usr/share/icons/hicolor/scalable/apps/nexus-system-doctor.svg"

# --- documentation -------------------------------------------------------
for f in README.md INSTALL.md SAFETY.md CHANGELOG.md LICENSE; do
    [ -f "$SRC/$f" ] && install -m 0644 "$SRC/$f" \
        "$STAGE/usr/share/doc/nexus-system-doctor/$f" || true
done
for f in "$SRC"/docs/screenshots/*.png "$SRC"/docs/sample-report.html; do
    [ -f "$f" ] && install -m 0644 "$f" \
        "$STAGE/usr/share/doc/nexus-system-doctor/screenshots/$(basename "$f")" || true
done

# --- package metadata ----------------------------------------------------
cp -a "$SRC/packaging/deb/DEBIAN" "$STAGE/DEBIAN"
chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm" 2>/dev/null || true

# Strip caches and editor files so the package stays small and clean.
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -name '*.pyc' -delete 2>/dev/null || true
find "$STAGE" -name '.DS_Store' -delete 2>/dev/null || true

SIZE=$(du -sk "$STAGE" | cut -f1)
echo "  staged size: ${SIZE} KB"

dpkg-deb --build --root-owner-group "$STAGE" "$PKG" >/dev/null
echo "  built: $PKG"

# A quick sanity check: list the contents and verify the control file.
dpkg-deb --info "$PKG" | sed -n '2,8p'
echo
echo "Contents:"
dpkg-deb --contents "$PKG" | awk '{print "  " $6, $7, $8}' | head -20
echo "  ... ($(dpkg-deb --contents "$PKG" | wc -l) entries total)"

rm -rf "$STAGE"
echo
echo "Done. Install with:"
echo "    sudo apt install \"$PKG\""
