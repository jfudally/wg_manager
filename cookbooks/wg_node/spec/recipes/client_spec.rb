# ChefSpec for wg_node::client — validation, resource declaration, and
# (stepping into the custom resource) the idempotent self-join action.

require_relative '../spec_helper'

RSpec.describe 'wg_node::client' do
  let(:base_attrs) do
    {
      'role' => 'client',
      'api_url' => 'https://wg-api.example.com:8000',
      'server_id' => 4,
      'tls' => {
        'verify' => true,
        'client_cert' => "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n",
        'client_key' => "-----BEGIN PRIVATE KEY-----\nXYZ\n-----END PRIVATE KEY-----\n",
        'ca_bundle' => "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
        'data_bag' => { 'name' => nil, 'item' => nil, 'keys' => {} },
      },
    }
  end

  def runner(extra = {})
    ChefSpec::SoloRunner.new do |node|
      node.normal['wg_node'] = Chef::Mixin::DeepMerge.merge(base_attrs, extra)
    end
  end

  context 'configuration' do
    subject(:chef_run) { runner('client_name' => 'node-a').converge(described_recipe) }

    it 'installs the WireGuard package' do
      expect(chef_run).to install_package('wireguard')
    end

    it 'declares the wg_node_client join with the API + mTLS settings' do
      res = chef_run.find_resource('wg_node_client', 'node-a')
      expect(res.server_id).to eq(4)
      expect(res.api_url).to eq('https://wg-api.example.com:8000')
      expect(res.api_version).to eq('v1')
      expect(res.interface).to eq('wg0')
      expect(res.tls_verify).to be(true)
      expect(res.client_cert).to include('BEGIN CERTIFICATE')
      expect(res.client_key).to include('BEGIN PRIVATE KEY')
      expect(res.ca_bundle).to include('BEGIN CERTIFICATE')
    end

    it 'defaults the client name to the node hostname' do
      chef_run = runner.converge(described_recipe)
      expect(chef_run.find_resource('wg_node_client', chef_run.node['hostname'])).not_to be_nil
    end

    it 'skips the package when manage_package is false' do
      chef_run = runner('manage_package' => false).converge(described_recipe)
      expect(chef_run).to_not install_package('wireguard')
    end

    it 'reads the CA from ca_path when no inline ca_bundle is set' do
      ca_pem = "-----BEGIN CERTIFICATE-----\nFROMFILE\n-----END CERTIFICATE-----\n"
      allow(File).to receive(:exist?).and_call_original
      allow(File).to receive(:exist?).with('/etc/wg_node/ca.crt').and_return(true)
      allow(File).to receive(:read).and_call_original
      allow(File).to receive(:read).with('/etc/wg_node/ca.crt').and_return(ca_pem)

      chef_run = runner(
        'client_name' => 'node-a',
        'tls' => { 'ca_bundle' => nil, 'ca_path' => '/etc/wg_node/ca.crt' }
      ).converge(described_recipe)

      expect(chef_run.find_resource('wg_node_client', 'node-a').ca_bundle).to eq(ca_pem)
    end

    it 'fails clearly when ca_path is set but missing' do
      allow(File).to receive(:exist?).and_call_original
      allow(File).to receive(:exist?).with('/etc/wg_node/missing.crt').and_return(false)

      expect do
        runner('tls' => { 'ca_bundle' => nil, 'ca_path' => '/etc/wg_node/missing.crt' })
          .converge(described_recipe)
      end.to raise_error(%r{ca_path /etc/wg_node/missing.crt does not exist})
    end
  end

  context 'CA trust install' do
    subject(:chef_run) { runner('client_name' => 'node-a').converge(described_recipe) }

    it 'writes the wg_manager CA into the system trust anchors' do
      res = chef_run.find_resource('file', '/usr/local/share/ca-certificates/wg_manager-ca.crt')
      expect(res.content).to include('BEGIN CERTIFICATE')
      expect(res.mode).to eq('0644')
    end

    it 'refreshes the trust store when the CA changes' do
      anchor = chef_run.file('/usr/local/share/ca-certificates/wg_manager-ca.crt')
      expect(anchor).to notify('execute[update-ca-certificates]').to(:run).immediately
    end

    it 'does not touch the trust store when install_ca is false' do
      chef_run = runner('client_name' => 'node-a', 'tls' => { 'install_ca' => false })
                 .converge(described_recipe)
      expect(chef_run).to_not create_file('/usr/local/share/ca-certificates/wg_manager-ca.crt')
    end

    it 'does nothing when there is no CA to install' do
      chef_run = runner('client_name' => 'node-a', 'tls' => { 'ca_bundle' => nil })
                 .converge(described_recipe)
      expect(chef_run).to_not create_file('/usr/local/share/ca-certificates/wg_manager-ca.crt')
    end
  end

  context 'validation' do
    it 'fails fast when api_url is missing' do
      expect { runner('api_url' => nil).converge(described_recipe) }
        .to raise_error(/api_url.* is required/)
    end

    it 'fails fast when server_id is missing' do
      expect { runner('server_id' => nil).converge(described_recipe) }
        .to raise_error(/server_id.* is required/)
    end
  end

  context 'self-join action (stepping into wg_node_client)' do
    let(:wg_config) do
      "[Interface]\nPrivateKey = SECRET\nAddress = 10.9.0.5/32\n"
    end
    let(:api_response) do
      { 'wg_config' => wg_config, 'client' => { 'id' => 7, 'address' => '10.9.0.5/32' } }
    end

    def join_runner
      ChefSpec::SoloRunner.new(step_into: ['wg_node_client']) do |node|
        node.normal['wg_node'] = Chef::Mixin::DeepMerge.merge(base_attrs, 'client_name' => 'node-a')
      end
    end

    before do
      stub_command('ip link show wg0').and_return(false)
      allow(File).to receive(:exist?).and_call_original
      allow(File).to receive(:exist?).with('/etc/wireguard/wg0.conf').and_return(true)
    end

    context 'when not yet joined' do
      before do
        allow(File).to receive(:exist?).with('/var/lib/wg_node/wg0.json').and_return(false)
        allow_any_instance_of(WgManager::ApiClient)
          .to receive(:register_manual_client)
          .with(name: 'node-a', server_id: 4)
          .and_return(api_response)
      end

      subject(:chef_run) { join_runner.converge('wg_node::client') }

      it 'writes the returned tunnel config (sensitive, 0600)' do
        res = chef_run.find_resource('file', '/etc/wireguard/wg0.conf')
        expect(res.content).to eq(wg_config)
        expect(res.mode).to eq('0600')
        expect(res.sensitive).to be(true)
      end

      it 'writes a join-state marker' do
        expect(chef_run).to create_file('/var/lib/wg_node/wg0.json')
      end

      it 'enables and starts the wg-quick service' do
        expect(chef_run).to enable_service('wg-quick@wg0')
        expect(chef_run).to start_service('wg-quick@wg0')
      end

      it 'restarts the tunnel when the config is (re)written' do
        cfg = chef_run.file('/etc/wireguard/wg0.conf')
        expect(cfg).to notify('service[wg-quick@wg0]').to(:restart).delayed
      end

      it 'does not use a bare wg-quick down (which desyncs systemd state)' do
        expect(chef_run).to_not run_execute('wg-quick down wg0 (pre-join reset)')
      end
    end

    context 'self-heal when the interface is down' do
      before do
        allow(File).to receive(:exist?).with('/var/lib/wg_node/wg0.json').and_return(true)
      end

      it 'restarts wg-quick when config exists but the interface is missing' do
        # `ip link show wg0` already stubbed false (interface down) above.
        chef_run = join_runner.converge('wg_node::client')
        expect(chef_run).to run_execute('restart wg-quick@wg0 (interface down)')
      end

      it 'leaves a healthy interface alone (no flap)' do
        stub_command('ip link show wg0').and_return(true)
        chef_run = join_runner.converge('wg_node::client')
        expect(chef_run).to_not run_execute('restart wg-quick@wg0 (interface down)')
      end
    end

    context 'when already joined' do
      before do
        allow(File).to receive(:exist?).with('/var/lib/wg_node/wg0.json').and_return(true)
      end

      subject(:chef_run) { join_runner.converge('wg_node::client') }

      it 'does not call the API' do
        expect_any_instance_of(WgManager::ApiClient).to_not receive(:register_manual_client)
        chef_run
      end

      it 'does not rewrite the config' do
        expect(chef_run).to_not create_file('/etc/wireguard/wg0.conf')
      end

      it 'still reconciles the service so reboots recover' do
        expect(chef_run).to enable_service('wg-quick@wg0')
      end
    end
  end
end
