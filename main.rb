require 'yaml'
require_relative 'capture'

def config_file
  region = ARGV[0]
  "#{region.downcase}-config.yml"
rescue StandardError
  'default-config.yml'
end

def init_config
  YAML.load_file(config_file)
rescue StandardError
  puts 'Could not load YAML config, exiting.'
  exit(-1)
end

def capture_int
  @config['interface'] || 'default'
end

@config = init_config
sev = ServiceEndpointValidator::PacketCapture.new
interface = sev.choose_interface(capture_int)
sev.start_capture(interface)
