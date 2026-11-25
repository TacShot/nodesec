#!/bin/bash
# nodesec net-installer redirector
# Redirects to the real installer in installer/install.sh

curl -fsSL https://raw.githubusercontent.com/TacShot/nodesec/main/installer/install.sh | bash
