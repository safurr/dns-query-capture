module ServiceEndpointValidator
  # Validate DNS request has a readable domain.
  class RequestChecker
    require 'packetfu'

    def readable(raw_domain)
      # Prevent processing non domain
      return true unless raw_domain[0].ord.zero?
    end

    def build_hostname(raw_domain)
      length_offset = raw_domain[0].ord
      full_length = raw_domain[0..length_offset].length
      domain_name = raw_domain[(full_length - length_offset)..length_offset]
      fqdn = parse_bytes(length_offset, full_length, domain_name, raw_domain)
      fqdn.chomp!('.')
    end

    def parse_bytes(length_offset, full_length, domain_name, raw_domain)
      fqdn = ''
      while length_offset != 0
        fqdn << domain_name + '.'
        length_offset = raw_domain[full_length].ord
        domain_name = raw_domain[full_length + 1..full_length + length_offset]
        full_length = raw_domain[0..full_length + length_offset].length
      end
      fqdn
    end
  end
end
