# InSpec controls asserting the post-converge state of a client node.
# Run by Test Kitchen against a converged guest (Phase 3, see ROADMAP.md).

control 'wg_node-config' do
  impact 1.0
  title 'WireGuard tunnel config is installed and locked down'
  desc 'wg_node::client must render /etc/wireguard/wg0.conf as root-only.'
  describe file('/etc/wireguard/wg0.conf') do
    it { should exist }
    its('mode') { should cmp '0600' }
    its('content') { should match(/\[Interface\]/) }
    its('content') { should match(/\[Peer\]/) }
  end
end

control 'wg_node-state-marker' do
  impact 0.5
  title 'Join-state marker is written so re-runs are idempotent'
  desc 'The marker lets later converges skip re-registration.'
  describe file('/var/lib/wg_node/wg0.json') do
    it { should exist }
    its('mode') { should cmp '0600' }
  end
end

control 'wg_node-service' do
  impact 1.0
  title 'wg-quick@wg0 service is enabled and running'
  desc 'The tunnel must survive reboots and be active after converge.'
  describe service('wg-quick@wg0') do
    it { should be_enabled }
    it { should be_running }
  end
end

control 'wg_node-interface' do
  impact 0.5
  title 'wg0 interface is present'
  desc 'wg show should report the interface once the tunnel is up.'
  describe command('wg show wg0') do
    its('exit_status') { should eq 0 }
  end
end
