module ServiceEndpointValidator
  # Take packets and perform analysis
  class PacketAnalysis
    require 'packetfu'
    require_relative 'response_validation'

    def initialize
      @is_query = "\x01\x00".unpack('H*')
      @is_response = "\x81\x80".unpack('H*')
      @is_nxdomain = "\x81\x83".unpack('H*')
    end

    def analyze(packet)
      dns_query_type, domain_name = get_dns_data(packet)
      request_checker = ServiceEndpointValidator::RequestChecker.new
      readable = request_checker.readable(domain_name)
      return unless readable
      fqdn = request_checker.build_hostname(domain_name)
      return unless fqdn
      format_response(packet, dns_query_type, fqdn)
    end

    def format_response(packet, dns_query_type, fqdn)
      return [fqdn, query_id(packet), 'DNS Query'] if
      dns_query_type.unpack('H*') == @is_query
      return [fqdn, query_id(packet), 'DNS Response'] if
      dns_query_type.unpack('H*') == @is_response
      return [fqdn, query_id(packet), 'DNS NXDOMAIN'] if
      dns_query_type.unpack('H*') == @is_nxdomain
    end

    def query_id(packet)
      packet.payload[0..1].to_s.unpack('H*')
    end

    def get_dns_data(packet)
      [packet.payload[2..3].to_s, packet.payload[12..-1].to_s]
    end
  end
end
