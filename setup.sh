#!/bin/bash
set -e
echo "Installing Engineering Gate v4.0..."
cp -r engineering-gate ~/.hermes/plugins/
echo "Add 'engineering-gate' to plugins.enabled in config.yaml"
echo "Run: hermes gateway restart"
