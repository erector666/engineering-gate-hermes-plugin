#!/usr/bin/env bash
# Engineering Gate Hermes Plugin — setup script
# Usage: ./setup.sh
set -euo pipefail

PLUGIN_SRC="$(cd "$(dirname "$0")" && pwd)/engineering-gate"
HERMES_PLUGINS="${HERMES_HOME:-$HOME/.hermes}/plugins"
TARGET="$HERMES_PLUGINS/engineering-gate"

echo "==> Installing Engineering Gate Hermes Plugin..."

mkdir -p "$TARGET"
cp "$PLUGIN_SRC/__init__.py" "$TARGET/"
cp "$PLUGIN_SRC/plugin.yaml" "$TARGET/"
echo "    Plugin files copied -> $TARGET"

CONFIG="${HERMES_HOME:-$HOME/.hermes}/config.yaml"
if [ -f "$CONFIG" ]; then
    if grep -q "plugins:" "$CONFIG" 2>/dev/null && ! grep -q "engineering-gate" "$CONFIG" 2>/dev/null; then
        python3 -c "
import yaml
with open('$CONFIG') as f:
    cfg = yaml.safe_load(f)
if not isinstance(cfg.get('plugins'), list):
    cfg['plugins'] = cfg.get('plugins') or []
if 'engineering-gate' not in cfg['plugins']:
    cfg['plugins'].append('engineering-gate')
with open('$CONFIG', 'w') as f:
    yaml.safe_dump(cfg, f, default_flow_style=False)
"
        echo "    Enabled in config.yaml"
    elif ! grep -q "plugins:" "$CONFIG" 2>/dev/null; then
        { echo "plugins:"; echo "  - engineering-gate"; } >> "$CONFIG"
        echo "    Enabled in config.yaml"
    else
        echo "    Already enabled in config.yaml"
    fi
fi

chmod +x "$TARGET/__init__.py"
echo "==> Done. Restart Hermes (/new) to activate."
