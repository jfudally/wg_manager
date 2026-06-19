# wg_node_client — register this node as a WireGuard client with the
# wg_manager API and bring the tunnel up, idempotently.
#
# The :join action calls POST /v1/clients/manual once (guarded by a
# state-marker file), writes the returned config to /etc/wireguard, and
# ensures the wg-quick@<iface> service is enabled and running on every
# converge. Because the private key in the response is shown exactly once,
# the rendered config and the marker are written together on first join;
# later runs only reconcile the service state.

unified_mode true

provides :wg_node_client

property :client_name, String, name_property: true,
                               description: 'Unique client name to register with wg_manager.'

property :server_id, Integer, required: true,
                              description: 'Id of the wg_manager server/hub this client attaches to.'

property :api_url, String, required: true,
                           description: 'Base URL of the wg_manager API, e.g. https://wg-api.example.com:8000.'

property :api_version, String, default: 'v1'

property :interface, String, default: 'wg0',
                             description: 'WireGuard interface name to manage.'

property :config_path, String,
         description: 'Path to the rendered tunnel config. Defaults to /etc/wireguard/<iface>.conf.'

property :state_path, String,
         description: 'Path to the join-state marker. Defaults to /var/lib/wg_node/<iface>.json.'

property :client_cert, String, sensitive: true,
                               description: 'Operator mTLS client certificate (PEM).'

property :client_key, String, sensitive: true,
                              description: 'Operator mTLS client private key (PEM).'

property :ca_bundle, String,
         description: 'CA bundle (PEM) used to verify the API server certificate.'

property :tls_verify, [true, false], default: true

# Resolved-path helpers so both the action and specs agree on defaults.
def resolved_config_path
  config_path || "/etc/wireguard/#{interface}.conf"
end

def resolved_state_path
  state_path || "/var/lib/wg_node/#{interface}.json"
end

action :join do
  cfg_path = new_resource.resolved_config_path
  state = new_resource.resolved_state_path

  unless ::File.exist?(state)
    response = nil
    converge_by("register #{new_resource.client_name} with wg_manager (#{new_resource.api_url})") do
      response = api_client.register_manual_client(
        name: new_resource.client_name,
        server_id: new_resource.server_id
      )
    end

    # Ensure parent directories for the config and state marker exist.
    [::File.dirname(cfg_path), ::File.dirname(state)].uniq.each do |dir|
      directory dir do
        recursive true
        owner 'root'
        group 'root'
        mode '0700'
      end
    end

    # Reprovision safety (see memory: tear down a running interface before
    # writing a fresh config). On a true first join the interface won't
    # exist; the guard keeps this a no-op in that case.
    iface = new_resource.interface
    execute "wg-quick down #{iface} (pre-join reset)" do
      command "wg-quick down #{iface}"
      only_if "ip link show #{iface}"
    end

    file cfg_path do
      content response.fetch('wg_config')
      owner 'root'
      group 'root'
      mode '0600'
      sensitive true
    end

    file state do
      content JSON.pretty_generate(
        'client_name' => new_resource.client_name,
        'server_id' => new_resource.server_id,
        'interface' => iface,
        'client' => response['client'],
        'api_url' => new_resource.api_url
      )
      owner 'root'
      group 'root'
      mode '0600'
      sensitive true
    end
  end

  # Always reconcile the service so a rebooted or stopped node comes back
  # up. Idempotent: starts only if not already running.
  service "wg-quick@#{new_resource.interface}" do
    action [:enable, :start]
    only_if { ::File.exist?(cfg_path) }
  end
end

action_class do
  # Build an API client from the resource's connection + mTLS properties.
  def api_client
    WgManager::ApiClient.new(
      base_url: new_resource.api_url,
      api_version: new_resource.api_version,
      client_cert_pem: new_resource.client_cert,
      client_key_pem: new_resource.client_key,
      ca_bundle_pem: new_resource.ca_bundle,
      tls_verify: new_resource.tls_verify
    )
  end
end
