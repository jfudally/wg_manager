# wg_node::client — self-provision this node as a WireGuard client.
#
# Validates configuration, installs WireGuard, resolves the mTLS material
# (from an encrypted data bag when configured, else from attributes), and
# hands off to the wg_node_client resource to register with the API and
# bring the tunnel up.

api_url = node['wg_node']['api_url']
raise "wg_node: node['wg_node']['api_url'] is required (e.g. https://wg-api.example.com:8000)." if api_url.to_s.empty?

server_id = node['wg_node']['server_id']
raise "wg_node: node['wg_node']['server_id'] is required for the client role." if server_id.nil?

# Default the client name to the node's hostname so a freshly imaged box
# joins under a predictable, unique identifier.
client_name = node['wg_node']['client_name'] || node['hostname']

# Resolve mTLS credentials: prefer an encrypted data bag item when one is
# configured, falling back to plain attributes for anything it omits.
creds = {
  'client_cert' => node['wg_node']['tls']['client_cert'],
  'client_key' => node['wg_node']['tls']['client_key'],
  'ca_bundle' => node['wg_node']['tls']['ca_bundle'],
}

bag = node['wg_node']['tls']['data_bag']
if bag && !bag['name'].to_s.empty? && !bag['item'].to_s.empty?
  item = data_bag_item(bag['name'], bag['item'])
  (bag['keys'] || {}).each do |cred_key, bag_key|
    value = item[bag_key]
    creds[cred_key] = value unless value.to_s.empty?
  end
end

# Fall back to a CA file on the node when no inline bundle was supplied.
# This is the easy path for self-signed / private-CA wg_manager servers.
ca_path = node['wg_node']['tls']['ca_path']
if creds['ca_bundle'].to_s.empty? && !ca_path.to_s.empty?
  raise "wg_node: tls.ca_path #{ca_path} does not exist on this node." unless ::File.exist?(ca_path)

  creds['ca_bundle'] = ::File.read(ca_path)
end

if node['wg_node']['tls']['verify'] && creds['ca_bundle'].to_s.empty?
  Chef::Log.warn(
    'wg_node: tls.verify is true but no ca_bundle/ca_path was provided; the ' \
    "API server certificate will be checked against the host's system trust " \
    'store, which will fail for a self-signed or private-CA wg_manager server.'
  )
end

# Install the wg_manager CA into the node's OS trust store so the API call
# (and curl, etc.) trusts the self-signed / private-CA server with no manual
# steps. Debian/Ubuntu path; RHEL is tracked in ROADMAP.md. The wg_node_client
# resource also passes the CA to the API client directly, so this works even
# before the system store is refreshed.
if !creds['ca_bundle'].to_s.strip.empty? && node['wg_node']['tls']['install_ca']
  directory '/usr/local/share/ca-certificates' do
    owner 'root'
    group 'root'
    mode '0755'
    recursive true
  end

  execute 'update-ca-certificates' do
    command 'update-ca-certificates'
    action :nothing
  end

  file '/usr/local/share/ca-certificates/wg_manager-ca.crt' do
    content creds['ca_bundle']
    owner 'root'
    group 'root'
    mode '0644'
    notifies :run, 'execute[update-ca-certificates]', :immediately
  end
end

# Install WireGuard unless the base image already provides it.
package node['wg_node']['package_name'] do
  only_if { node['wg_node']['manage_package'] }
end

wg_node_client client_name do
  server_id    server_id.to_i
  api_url      api_url
  api_version  node['wg_node']['api_version']
  interface    node['wg_node']['interface']
  config_path  node['wg_node']['config_path'] if node['wg_node']['config_path']
  state_path   node['wg_node']['state_path'] if node['wg_node']['state_path']
  client_cert  creds['client_cert']
  client_key   creds['client_key']
  ca_bundle    creds['ca_bundle']
  tls_verify   node['wg_node']['tls']['verify']
  action :join
end
