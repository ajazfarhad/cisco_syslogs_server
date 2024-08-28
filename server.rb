require 'socket'
require 'snmp'
require 'concurrent-ruby'
require 'json'
require 'thread'

# Constants
SNMP_COMMUNITY = 'community_string'  # Replace with your SNMP community string
NETWORK_ADDR = "10.6.26"
SWITCH_IPS = (1..10).map { |i| "#{NETWORK_ADDR}.#{i}" }
UPTIME_OID = '1.3.6.1.2.1.1.3.0'
SYS_NAME_OID = '1.3.6.1.2.1.1.5.0'
CHECK_INTERVAL = 30

class UnifiedMonitor
  def initialize(syslog_port = 514)
    @syslog_port = syslog_port
    @server = UDPSocket.new
    @server.bind('0.0.0.0', @syslog_port)
    @message_queue = Queue.new
    @processor_pool = Concurrent::FixedThreadPool.new(5)
    @checker_pool = Concurrent::FixedThreadPool.new(10)
    puts "Syslog receiver running on port #{@syslog_port}"
  end

  def start
    Concurrent::Promises.future { listen_for_syslog_messages }
    Concurrent::Promises.future { snmp_check_loop }
    @processor_pool.post { process_syslog_messages }
    wait_forever
  end

  private

  def listen_for_syslog_messages
    loop do
      message, addr = @server.recvfrom(1024)
      ip_address = addr[3]

      if SWITCH_IPS.include?(ip_address)
        @message_queue << { message: message, ip: ip_address }
      end
    end
  end

  def process_syslog_messages
    loop do
      begin
        log_entry = @message_queue.pop(true)
        handle_syslog_message(log_entry)
      rescue ThreadError
        sleep(0.1)
      end
    end
  end

  def handle_syslog_message(log_entry)
    message = log_entry[:message]
    ip_address = log_entry[:ip]
    switch_name = snmp_status_check(ip_address, SNMP_COMMUNITY)
    puts "Received syslog message from #{ip_address}: #{message} : #{switch_name}"
    log_event = LogEvent.new(message: message, ip: ip_address, switch_name: switch_name)
    post_log_event(log_event)
  end

  def post_log_event(log_event)
    # Post the LogEvent to the API server or API Gateway Endpoint
  end

  def fetch_snmp_data(ip, community, oids)
    SNMP::Manager.open(host: ip, community: community) do |manager|
      response = manager.get(oids)
      yield(response) if block_given?
    end
  rescue SNMP::RequestTimeout
    yield(nil) if block_given?
  rescue StandardError => e
    puts "An error occurred: #{e.message}"
    yield(nil) if block_given?
  end

  def snmp_status_check(ip, community)
    fetch_snmp_data(ip, community, [SYS_NAME_OID]) do |response|
      return response&.varbind_list&.first&.value&.to_s || "Unknown"
    end
  end

  def perform_uptime_status_check(ip)
    fetch_snmp_data(ip, SNMP_COMMUNITY, [UPTIME_OID]) do |response|
      if response
        uptime = response.varbind_list.first.value
        UptimeStatus.new(up: true, uptime: uptime, ip: ip)
      else
        UptimeStatus.new(up: false, ip: ip)
      end
    end
  end

  def snmp_check_loop
    loop do
      check_all_switches
      sleep CHECK_INTERVAL
    end
  end

  def check_all_switches
    SWITCH_IPS.each do |ip|
      @checker_pool.post { check_switch(ip) }
    end
  end

  def check_switch(ip)
    uptime_status = perform_uptime_status_check(ip)
    # puts uptime_status.status_info
    post_uptime_status(uptime_status)
  end

  def post_uptime_status(uptime_status)
    # Post the uptime status to the API server or API Gateway Endpoint
  end

  def wait_forever
    loop { sleep 1 }
  end

  UptimeStatus = Struct.new(:up, :uptime, :ip, :checked_at, keyword_init: true) do
    def status_info
      {
        up: up,
        uptime: uptime,
        ip: ip,
        checked_at: Time.now
      }.to_json
    end
  end

  LogEvent = Struct.new(:message, :ip, :switch_name, keyword_init: true) do
    def info
      {
        message: message,
        ip: ip,
        switch_name: switch_name
      }.to_json
    end
  end
end

UnifiedMonitor.new.start
