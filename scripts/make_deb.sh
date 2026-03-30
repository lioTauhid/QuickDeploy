#!/bin/bash

# Script to create a .deb package from a binary, with optional GUI support
# Usage: ./make_deb.sh "QuickDeploy" "0.9" "QuickDeploy" "A PyQt6 desktop GUI application for automating web app deployment to remote servers (EC2, VPS, etc.). This tool allows you to deploy multiple web applications, manage remote files, and access an interactive terminal—all from a single interface." "QuickDeploy" "/home/tauhid-atb/PycharmProjects/QuickDeploy/assets/logo.png" "Utility;"

if [ "$#" -lt 4 ]; then
    echo "Usage: $0 <package_name> <version> <binary_path> <description> [app_title] [icon_path] [categories]"
    exit 1
fi

PACKAGE_NAME=$1
VERSION=$2
BINARY_PATH=$3
DESCRIPTION=$4
APP_TITLE=${5:-$PACKAGE_NAME} # Defaults to package name if not provided
ICON_PATH=$6
CATEGORIES=${7:-Utility;} # Defaults to Utility if not provided
ARCH=$(dpkg --print-architecture)
DIR_NAME="${PACKAGE_NAME}_${VERSION}_${ARCH}"

# Create base directory structure
mkdir -p "${DIR_NAME}/usr/bin"
mkdir -p "${DIR_NAME}/DEBIAN"

# Copy binary
cp "${BINARY_PATH}" "${DIR_NAME}/usr/bin/${PACKAGE_NAME}"
chmod +x "${DIR_NAME}/usr/bin/${PACKAGE_NAME}"

# Create control file
cat <<EOF > "${DIR_NAME}/DEBIAN/control"
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: Md Tauhid - liotauhid@gmail.com
Description: ${DESCRIPTION}
EOF

# Handle GUI application specific files (.desktop and icon)
if [ -n "$ICON_PATH" ]; then
    ICON_NAME=$(basename "$ICON_PATH")
    ICON_DEST_DIR="${DIR_NAME}/usr/share/icons"
    mkdir -p "$ICON_DEST_DIR"
    cp "$ICON_PATH" "$ICON_DEST_DIR/$ICON_NAME"
    ICON_LINE="Icon=/usr/share/icons/$ICON_NAME"
else
    ICON_LINE=""
fi

# Create .desktop file if app_title is provided (indicating a GUI app)
if [ -n "$APP_TITLE" ]; then
    DESKTOP_FILE_DIR="${DIR_NAME}/usr/share/applications"
    mkdir -p "$DESKTOP_FILE_DIR"
    cat <<EOF > "$DESKTOP_FILE_DIR/${PACKAGE_NAME}.desktop"
[Desktop Entry]
Type=Application
Name=${APP_TITLE}
Exec=/usr/bin/${PACKAGE_NAME}
${ICON_LINE}
Terminal=false
Categories=${CATEGORIES}
EOF
fi

# Build the package
dpkg-deb --build --root-owner-group "${DIR_NAME}"

echo "Package ${DIR_NAME}.deb created successfully!"

# to install app: sudo dpkg -i QuickDeploy_0.9_amd64.deb
