# Unit specs for WgManager::ApiClient — the HTTP client the cookbook uses
# to self-register a node as a WireGuard client against the wg_manager API.
#
# These stub Net::HTTP directly (WebMock is not bundled with Chef
# Workstation) so we can assert on the request that would go over the wire
# and on the mTLS configuration, without opening a socket.

require_relative '../spec_helper'
require 'json'
require 'openssl'

RSpec.describe WgManager::ApiClient do
  # A minimal stand-in for Net::HTTP. It records the configuration the
  # client applies (so we can assert mTLS is wired up) and returns a
  # canned response from #request.
  class FakeHTTP
    attr_accessor :use_ssl, :verify_mode, :cert, :key, :cert_store,
                  :open_timeout, :read_timeout
    attr_reader :requests

    def initialize(response)
      @response = response
      @requests = []
    end

    def use_ssl?
      @use_ssl
    end

    def request(req)
      @requests << req
      @response
    end
  end

  # Ephemeral self-signed cert/key so the client can build real OpenSSL
  # objects without us shipping fixtures. Generated once per run.
  before(:all) do
    key = OpenSSL::PKey::RSA.new(2048)
    name = OpenSSL::X509::Name.parse('/CN=test-node')
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = name
    cert.issuer = name
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    @cert_pem = cert.to_pem
    @key_pem = key.to_pem
    @ca_pem = cert.to_pem
  end

  let(:wg_config) do
    "[Interface]\nPrivateKey = SECRET\nAddress = 10.9.0.5/32\n\n" \
      "[Peer]\nPublicKey = HUBKEY\nEndpoint = vpn.example.com:51820\n" \
      "AllowedIPs = 10.9.0.0/24\nPersistentKeepalive = 25\n"
  end

  let(:success_payload) do
    {
      'task_id' => 'task-123',
      'client' => { 'id' => 7, 'name' => 'node-a', 'address' => '10.9.0.5/32' },
      'wg_config' => wg_config,
    }
  end

  def http_response(code, body)
    instance_double(Net::HTTPResponse, code: code.to_s, body: body)
  end

  let(:response) { http_response(201, JSON.generate(success_payload)) }
  let(:fake_http) { FakeHTTP.new(response) }

  before do
    allow(Net::HTTP).to receive(:new).and_return(fake_http)
  end

  subject(:client) do
    described_class.new(
      base_url: 'https://wg-api.example.com:8000/',
      api_version: 'v1',
      client_cert_pem: @cert_pem,
      client_key_pem: @key_pem,
      ca_bundle_pem: @ca_pem
    )
  end

  describe '#register_manual_client' do
    it 'POSTs name + server_id as JSON to the versioned manual-client path' do
      client.register_manual_client(name: 'node-a', server_id: 3)

      req = fake_http.requests.first
      expect(req).to be_a(Net::HTTP::Post)
      expect(req.path).to eq('/v1/clients/manual')
      expect(req['Content-Type']).to eq('application/json')
      expect(JSON.parse(req.body)).to eq('name' => 'node-a', 'server_id' => 3)
    end

    it 'returns the parsed response including the one-time wg_config' do
      result = client.register_manual_client(name: 'node-a', server_id: 3)

      expect(result['wg_config']).to eq(wg_config)
      expect(result['client']['id']).to eq(7)
      expect(result['task_id']).to eq('task-123')
    end

    it 'configures mutual TLS (client cert, key, peer verification)' do
      client.register_manual_client(name: 'node-a', server_id: 3)

      expect(fake_http.use_ssl?).to be(true)
      expect(fake_http.verify_mode).to eq(OpenSSL::SSL::VERIFY_PEER)
      expect(fake_http.cert).to be_a(OpenSSL::X509::Certificate)
      expect(fake_http.key).to be_a(OpenSSL::PKey::PKey)
      expect(fake_http.cert_store).to be_a(OpenSSL::X509::Store)
    end

    it 'disables peer verification when tls_verify is false' do
      insecure = described_class.new(
        base_url: 'https://wg-api.example.com:8000',
        client_cert_pem: @cert_pem,
        client_key_pem: @key_pem,
        tls_verify: false
      )
      insecure.register_manual_client(name: 'node-a', server_id: 3)

      expect(fake_http.verify_mode).to eq(OpenSSL::SSL::VERIFY_NONE)
    end

    it 'raises ApiError carrying the status and body on a non-2xx response' do
      allow(fake_http).to receive(:request).and_return(
        http_response(409, '{"detail":"client name already exists"}')
      )

      expect { client.register_manual_client(name: 'dupe', server_id: 3) }
        .to raise_error(WgManager::ApiError) { |err|
          expect(err.status).to eq(409)
          expect(err.body).to include('already exists')
        }
    end

    it 'raises an actionable ApiError when the server cert is untrusted' do
      allow(fake_http).to receive(:request).and_raise(
        OpenSSL::SSL::SSLError.new('certificate verify failed (self-signed certificate in certificate chain)')
      )

      expect { client.register_manual_client(name: 'node-a', server_id: 3) }
        .to raise_error(WgManager::ApiError) { |err|
          expect(err.message).to match(/TLS verification/i)
          expect(err.message).to match(/ca_bundle|ca_path/)
          expect(err.message).to match(/verify/)
        }
    end

    it 'raises an mTLS-specific ApiError when the server demands a client cert' do
      allow(fake_http).to receive(:request).and_raise(
        OpenSSL::SSL::SSLError.new('SSL_read: unexpected eof while reading')
      )

      expect { client.register_manual_client(name: 'node-a', server_id: 3) }
        .to raise_error(WgManager::ApiError) { |err|
          expect(err.message).to match(/client certificate|mTLS/i)
          expect(err.message).to match(/client_cert/)
        }
    end

    it 'raises ApiError when a 2xx response is missing wg_config' do
      allow(fake_http).to receive(:request).and_return(
        http_response(201, JSON.generate('task_id' => 'task-9', 'client' => {}))
      )

      expect { client.register_manual_client(name: 'node-a', server_id: 3) }
        .to raise_error(WgManager::ApiError, /wg_config/)
    end

    it 'raises ApiError when the response body is not valid JSON' do
      allow(fake_http).to receive(:request).and_return(
        http_response(201, 'not-json{')
      )

      expect { client.register_manual_client(name: 'node-a', server_id: 3) }
        .to raise_error(WgManager::ApiError, /JSON/i)
    end
  end

  describe 'URL construction' do
    it 'joins base_url and version without producing double slashes' do
      client.register_manual_client(name: 'node-a', server_id: 3)
      # Net::HTTP.new is called with host and port parsed from the URI.
      expect(Net::HTTP).to have_received(:new).with('wg-api.example.com', 8000)
    end

    it 'uses plain HTTP (no SSL) when base_url is http' do
      plain = described_class.new(base_url: 'http://localhost:8000', api_version: 'v1')
      plain.register_manual_client(name: 'node-a', server_id: 3)
      expect(fake_http.use_ssl?).to be_falsey
    end
  end
end
