# frozen_string_literal: true

# WgManager::ApiClient — a small HTTP client the wg_node cookbook uses to
# self-register a node onto a WireGuard VPN via the wg_manager control
# plane.
#
# The only call Phase 1 needs is `POST /{version}/clients/manual`, which
# generates a keypair server-side and returns the full `wg0.conf` (with
# the private key inline, exactly once) in the response. The node writes
# that config to disk and brings the tunnel up itself — the control plane
# never SSHes in for this path.
#
# Auth is mutual TLS: every endpoint except /health requires an operator
# client certificate. Callers pass the cert/key/CA as PEM strings (sourced
# from an encrypted data bag in real deployments).
#
# This file is deliberately pure Ruby (no Chef DSL) so it can be unit
# tested in isolation and reasoned about on its own.

require 'net/http'
require 'uri'
require 'json'
require 'openssl'

module WgManager
  # Raised for any non-2xx response, malformed body, or missing expected
  # field. Carries the HTTP status and raw body when available so callers
  # (and Chef's error output) can show what the API actually said.
  class ApiError < StandardError
    attr_reader :status, :body

    def initialize(message, status: nil, body: nil)
      @status = status
      @body = body
      super(message)
    end
  end

  class ApiClient
    DEFAULT_OPEN_TIMEOUT = 10
    DEFAULT_READ_TIMEOUT = 30

    # @param base_url [String] scheme://host:port of the API, e.g.
    #   "https://wg-api.example.com:8000". A trailing slash is tolerated.
    # @param api_version [String] version prefix, default "v1".
    # @param client_cert_pem [String, nil] operator client cert (PEM).
    # @param client_key_pem [String, nil] operator client private key (PEM).
    # @param ca_bundle_pem [String, nil] CA bundle (PEM) used to verify the
    #   API server's certificate. Falls back to the system store when nil.
    # @param tls_verify [Boolean] verify the server cert (default true).
    #   Only set false for throwaway lab endpoints with self-signed certs.
    # @param open_timeout [Integer] connect timeout (seconds).
    # @param read_timeout [Integer] response timeout (seconds).
    def initialize(base_url:, api_version: 'v1', client_cert_pem: nil,
                   client_key_pem: nil, ca_bundle_pem: nil, tls_verify: true,
                   open_timeout: DEFAULT_OPEN_TIMEOUT,
                   read_timeout: DEFAULT_READ_TIMEOUT)
      @base_url = base_url.to_s
      @api_version = api_version.to_s
      @client_cert_pem = client_cert_pem
      @client_key_pem = client_key_pem
      @ca_bundle_pem = ca_bundle_pem
      @tls_verify = tls_verify
      @open_timeout = open_timeout
      @read_timeout = read_timeout
    end

    # Register this node as a manual WireGuard client and return the parsed
    # response. The response includes `wg_config` — the full /etc/wireguard
    # config with the private key inline. This is the ONLY time the private
    # key is exposed, so the caller must persist it immediately.
    #
    # @param name [String] unique client name (the API rejects duplicates).
    # @param server_id [Integer] the hub/server this client attaches to.
    # @return [Hash] parsed JSON: task_id, client, wg_config.
    # @raise [ApiError] on a non-2xx response, bad JSON, or missing config.
    def register_manual_client(name:, server_id:)
      data = post_json('/clients/manual', 'name' => name, 'server_id' => server_id)

      unless data.is_a?(Hash) && data['wg_config'].is_a?(String) && !data['wg_config'].empty?
        raise ApiError.new(
          'wg_manager response did not include a wg_config body',
          status: 200, body: data.inspect
        )
      end

      data
    end

    private

    # POST a JSON payload to a versioned path and return the parsed body.
    def post_json(path, payload)
      uri = build_uri(path)
      http = build_http(uri)

      request = Net::HTTP::Post.new(uri)
      request['Content-Type'] = 'application/json'
      request['Accept'] = 'application/json'
      request.body = JSON.generate(payload)

      response =
        begin
          http.request(request)
        rescue OpenSSL::SSL::SSLError => e
          # A TLS error here is operational, not a code bug. Distinguish the
          # two common causes so the message points at the right knob:
          #   * server-cert distrust  -> CA / verify
          #   * server demands a client cert (mTLS) -> client_cert / client_key
          raise ApiError.new(tls_error_message(uri, e), body: e.message)
        rescue StandardError => e
          raise ApiError, "wg_manager API request to #{uri} failed: #{e.class}: #{e.message}"
        end

      handle_response(response, uri)
    end

    # Produce an actionable message for a TLS failure, branching on whether
    # the node distrusts the server cert or the server demanded (and didn't
    # get) a client certificate.
    def tls_error_message(uri, error)
      msg = error.message.to_s

      if msg =~ /certificate verify failed/i
        "wg_manager API TLS verification to #{uri} failed: #{msg}. " \
        'The node does not trust the API server certificate. Supply the ' \
        "wg_manager CA via node['wg_node']['tls']['ca_bundle'] or " \
        "node['wg_node']['tls']['ca_path'], or set " \
        "node['wg_node']['tls']['verify'] = false for a lab endpoint."
      elsif msg =~ /unexpected eof|alert (handshake failure|certificate)|bad certificate|peer did not return a certificate|no certificate|sslv3 alert|tlsv1[.0-9]* alert/i
        "wg_manager API TLS connection to #{uri} failed: #{msg}. The server " \
        'closed the TLS connection, which almost always means the wg_manager ' \
        'API requires a client certificate (mTLS) and none was sent. Provide ' \
        "an operator cert/key via node['wg_node']['tls']['client_cert'] and " \
        "node['wg_node']['tls']['client_key'] (or the encrypted data bag)."
      else
        "wg_manager API TLS handshake to #{uri} failed: #{msg}. Check " \
        "node['wg_node']['tls'] settings: ca_bundle/ca_path (server trust), " \
        'client_cert/client_key (mTLS), and verify.'
      end
    end

    # Build the absolute request URI from base_url + version + path,
    # collapsing any stray slashes so "base/" + "v1" + "/clients" stays a
    # single-slash join.
    def build_uri(path)
      base = @base_url.sub(%r{/+\z}, '')
      version = @api_version.sub(%r{\A/+}, '').sub(%r{/+\z}, '')
      leaf = path.sub(%r{\A/+}, '')
      URI.parse([base, version, leaf].reject(&:empty?).join('/'))
    end

    # Construct a configured Net::HTTP for the URI, wiring up mTLS when the
    # scheme is https.
    def build_http(uri)
      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = @open_timeout
      http.read_timeout = @read_timeout

      if uri.scheme == 'https'
        http.use_ssl = true
        http.verify_mode = @tls_verify ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
        http.cert = OpenSSL::X509::Certificate.new(@client_cert_pem) if @client_cert_pem
        http.key = OpenSSL::PKey.read(@client_key_pem) if @client_key_pem
        http.cert_store = build_cert_store(@ca_bundle_pem) if @ca_bundle_pem
      end

      http
    end

    # Build an X509 store seeded with the supplied CA bundle so the server
    # cert is verified against the wg_manager CA rather than the host's
    # system roots.
    def build_cert_store(ca_pem)
      store = OpenSSL::X509::Store.new
      # A bundle may concatenate several PEM certs; add each one.
      ca_pem.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m).each do |pem|
        store.add_cert(OpenSSL::X509::Certificate.new(pem))
      end
      store
    end

    # Turn an HTTP response into parsed JSON or an ApiError.
    def handle_response(response, uri)
      code = response.code.to_i

      unless (200..299).cover?(code)
        raise ApiError.new(
          "wg_manager API returned HTTP #{code} for #{uri}",
          status: code, body: response.body
        )
      end

      parse_json(response.body, code)
    end

    def parse_json(body, code)
      JSON.parse(body)
    rescue JSON::ParserError => e
      raise ApiError.new(
        "wg_manager API returned a body that is not valid JSON: #{e.message}",
        status: code, body: body
      )
    end
  end
end
