# wg_node::default — entry point. Dispatches to the role-specific recipe.
#
# Set node['wg_node']['role'] to choose what this node becomes. Phase 1
# supports 'client' only; 'server' raises a clear, actionable error.

role = node['wg_node']['role']

case role
when 'client'
  include_recipe 'wg_node::client'
when 'server'
  raise "wg_node: role 'server' is not supported yet. Phase 1 self-provisions " \
        'clients only. Server self-provisioning is tracked as Phase 2 in ' \
        'cookbooks/wg_node/ROADMAP.md. For now register servers through the ' \
        'wg_manager API (POST /v1/servers) or the `wg-manager servers register` CLI.'
else
  raise "wg_node: node['wg_node']['role'] must be 'client' (got #{role.inspect})."
end
