name 'wg_node'
maintainer 'Justin Fudally'
maintainer_email 'justinfudally@gmail.com'
license 'MIT'
description 'Self-provisions a node onto a WireGuard VPN via the wg_manager API'
version '0.1.4'
chef_version '>= 16.0'

# Phase 1 targets Debian-family hosts (the wg_manager worker installs the
# `wireguard` apt package). RHEL support is tracked in ROADMAP.md.
supports 'ubuntu'
supports 'debian'

issues_url 'https://github.com/jfudally/wg_manager/issues'
source_url 'https://github.com/jfudally/wg_manager'
