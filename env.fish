#!/usr/bin/env fish
# Source this file to add nsproxy tools to PATH
# Usage: . env.fish

set -l SCRIPT_DIR (dirname (status --current-filename))
set -gx PATH $SCRIPT_DIR/install $PATH

echo "Added $SCRIPT_DIR/install to PATH"
