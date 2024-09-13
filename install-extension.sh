#!/bin/bash

# Determine the operating system
OS="$(uname -s)"
NATIVE_APP_NAME="unibonn.netsec.fpki.extension"
NATIVE_APP_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/native-messaging-app"
JSON_PATH="$NATIVE_APP_DIR/native_app_manifest.json"

read -p "Enter extension ID (from chrome://extensions page): " EXTENSION_ID

# Replace placeholder in JSON with the correct script path
if [[ "$OS" == "Darwin" ]]; then
    SH_PATH="$NATIVE_APP_DIR/run_native_app.sh"
    sed -i.bak "s|path_to_script_based_on_os|$SH_PATH|" "$JSON_PATH"
    sed -i.bak "s|<extension id from chrome://extensions page>|$EXTENSION_ID|" "$JSON_PATH"
else
    SH_PATH="$NATIVE_APP_DIR/run_native_app.sh"
    sed -i "s|path_to_script_based_on_os|$SH_PATH|" "$JSON_PATH"
    sed -i "s|<extension id from chrome://extensions page>|$EXTENSION_ID|" "$JSON_PATH"
fi

# Function to copy manifest to the appropriate location
copy_manifest() {
    local target_dir="$1"
    local browser="$2"
    
    echo "Installing for $browser..."
    mkdir -p "$target_dir"
    cp "$JSON_PATH" "$target_dir/$NATIVE_APP_NAME.json"
}


# Function to copy manifest to the appropriate location
copy_manifest_with_sudo() {
    local target_dir="$1"
    local browser="$2"

    echo "Installing for $browser..."
    sudo mkdir -p "$target_dir"
    sudo cp "$JSON_PATH" "$target_dir/$NATIVE_APP_NAME.json"
}

# macOS paths
if [[ "$OS" == "Darwin" ]]; then
    echo "Detected macOS"

    # User-specific installation Chrome
    copy_manifest "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts" "Google Chrome (user-specific)"
    # User-specific installation Chromium
    copy_manifest "$HOME/Library/Application Support/Chromium/NativeMessagingHosts" "Chromium (user-specific)"
    
    # Comment out the following line if you want to install system-wide (requires sudo)
    # System-wide installation Chrome (requires sudo)
    #copy_manifest_with_sudo "/Library/Google/Chrome/NativeMessagingHosts" "Google Chrome (system-wide)"
    # System-wide installation Chromium (requires sudo)
    #copy_manifest_with_sudo "/Library/Application Support/Chromium/NativeMessagingHosts" "Chromium (system-wide)"

# Linux paths
elif [[ "$OS" == "Linux" ]]; then
    echo "Detected Linux"

    # User-specific installation for Chrome
    copy_manifest "$HOME/.config/google-chrome/NativeMessagingHosts" "Google Chrome (user-specific)"
    # User-specific installation for Chromium
    copy_manifest "$HOME/.config/chromium/NativeMessagingHosts" "Chromium (user-specific)"
    
    # Comment out the following lines if you want to install system-wide (requires sudo)
    # System-wide installation (requires sudo)
    #copy_manifest_with_sudo "/etc/opt/chrome/native-messaging-hosts" "Google Chrome (system-wide)"
    #copy_manifest_with_sudo "/etc/chromium/native-messaging-hosts" "Chromium (system-wide)"

else
    echo "Unsupported OS: $OS"
    exit 1
fi

echo "Installation complete."
