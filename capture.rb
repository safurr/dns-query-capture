module ServiceEndpointValidator
  # Get the packets
  class PacketCapture
    require 'packetfu'
    require_relative 'analyzer'

    def choose_interface(interface)
      case interface
      when 'default'
        PacketFu::Utils.default_int
      else
        interface
      end
    end

    def start_capture(interface)
      puts "Interface capture starting on: #{interface}"
      # cap_ip = PacketFu::Utils.ifconfig(@interface)[:ip_saddr]
      cap = PacketFu::Capture.new(iface: interface)
      cap.bpf(filter: 'port 53')
      cap.start
      cap.stream.each do |pkt|
        process_response(pkt)
      end
    end

    def process_response(pkt)
      if PacketFu::UDPPacket.can_parse?(pkt) ||
         PacketFu::TCPPacket.can_parse?(pkt)
        analyzer = ServiceEndpointValidator::PacketAnalysis.new
        packet = PacketFu::Packet.parse(pkt)
        fqdn, query_id, type = analyzer.analyze(packet)
        puts "#{Time.now.getutc},#{fqdn},#{query_id},#{type}"
      end
    end
  end
end
