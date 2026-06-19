# ChefSpec for wg_node::default — role dispatch.

require_relative '../spec_helper'

RSpec.describe 'wg_node::default' do
  def runner(role:)
    ChefSpec::SoloRunner.new do |node|
      node.normal['wg_node']['role'] = role
      node.normal['wg_node']['api_url'] = 'https://wg-api.example.com:8000'
      node.normal['wg_node']['server_id'] = 1
    end
  end

  it "includes the client recipe for role 'client'" do
    chef_run = runner(role: 'client').converge(described_recipe)
    expect(chef_run).to include_recipe('wg_node::client')
  end

  it "raises a Phase-2/ROADMAP error for role 'server'" do
    expect { runner(role: 'server').converge(described_recipe) }
      .to raise_error(/role 'server' is not supported yet.*ROADMAP/m)
  end

  it 'raises a clear error for an unknown role' do
    expect { runner(role: 'gateway').converge(described_recipe) }
      .to raise_error(/must be 'client'.*"gateway"/m)
  end
end
