require 'webrick'
require 'webrick/httpproxy'
require 'ritm/helpers/patches'
require 'ritm/interception/intercept_utils'

module WEBrick
  module HTTPAuth
    class BasicAuth
      include Authenticator

      AuthScheme = "Basic" # :nodoc:

      ##
      # Used by UserDB to create a basic password entry

      def self.make_passwd(realm, user, pass)
        pass ||= ""
        pass.crypt(Utils::random_string(2))
      end

      attr_reader :realm, :userdb, :logger

      ##
      # Creates a new BasicAuth instance.
      #
      # See WEBrick::Config::BasicAuth for default configuration entries
      #
      # You must supply the following configuration entries:
      #
      # :Realm:: The name of the realm being protected.
      # :UserDB:: A database of usernames and passwords.
      #           A WEBrick::HTTPAuth::Htpasswd instance should be used.

      def initialize(config, default=Config::BasicAuth)
        check_init(config)
        @config = default.dup.update(config)
      end

      ##
      # Authenticates a +req+ and returns a 401 Unauthorized using +res+ if
      # the authentication was not correct.

      def authenticate(req, res)
        unless basic_credentials = check_scheme(req)
          challenge(req, res)
        end
        userid, password = basic_credentials.unpack("m*")[0].split(":", 2)
        password ||= ""
        if userid.empty?
          error("user id was not given.")
          challenge(req, res)
        end

        unless ::Device.find_by(proxy_login: userid)
          error("%s: the user is not allowed.", userid)
          challenge(req, res)
        end

        $device = ::Device.find_by(proxy_login: userid, proxy_password: password)
        if not $device
          error("%s: password unmatch.", userid)
          challenge(req, res)
        end

        info("%s: authentication succeeded.", userid)

        req.user = userid
      end

      ##
      # Returns a challenge response which asks for authentication information

      def challenge(req, res)
        res[@response_field] = "#{@auth_scheme} realm=\"#{@realm}\""
        raise @auth_exception
      end
    end

    ##
    # Basic authentication for proxy servers.  See BasicAuth for details.

    class ProxyBasicAuth < BasicAuth
      include ProxyAuthenticator
    end
  end
end

module Ritm
  module Proxy
    # Proxy server that accepts request and response intercept handlers for HTTP traffic
    # HTTPS traffic is redirected to the SSLReverseProxy for interception
    class ProxyServer < WEBrick::HTTPProxyServer
      include InterceptUtils

      def start_async
        trap(:TERM) { shutdown }
        trap(:INT) { shutdown }
        Thread.new { start }
      end

      # Override
      # Patches the destination address on HTTPS connections to go via the HTTPS Reverse Proxy
      def do_CONNECT(req, res)
        req.unparsed_uri = @config[:https_forward] unless ssl_pass_through? req.unparsed_uri
        super
      end

      # Override
      # Handles HTTP (no SSL) traffic interception
      def proxy_service(req, res)
        # Proxy Authentication
        proxy_auth(req, res)

        # Request modifier handler
        intercept_request(@config[:request_interceptor], req)

        begin
          send("do_#{req.request_method}", req, res)
        rescue NoMethodError
          raise WEBrick::HTTPStatus::MethodNotAllowed, "unsupported method `#{req.request_method}'."
        rescue => err
          raise WEBrick::HTTPStatus::ServiceUnavailable, err.message
        end

        # Response modifier handler
        intercept_response(@config[:response_interceptor], req, res)
      end

      private

      def ssl_pass_through?(destination)
        Ritm.conf.misc.ssl_pass_through.each do |matcher|
          case matcher
          when String
            return true if destination == matcher
          when Regexp
            return true if destination =~ matcher
          end
        end
        false
      end
    end
  end
end
