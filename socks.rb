#!/usr/bin/env ruby
require 'socket'

class SocksRequest
	attr_reader :vn, :cd, :dstport, :dstip, :userid, :srcport, :srcip
	
	def initialize vn=nil, cd=nil, dstport=nil, dstip=nil, userid=nil, srcport=nil, srcip=nil
		@vn = vn
		@cd = cd
		@dstip = dstip
		@dstport = dstport
		@userid = userid
		@srcport = srcport
		@srcip = srcip
	end

	def unpack input
		array = input.unpack('C1C1n1C4A*')
		@vn = array[0]
		@cd = array[1]
		@dstport = array[2]
		@dstip = array[3].to_s + '.' + array[4].to_s + '.' + array[5].to_s + '.' + array[6].to_s
		@userid = array[7]
	end

	def pack
		# domain name to 4 byte ip
		ip = Socket.gethostbyname(@dstip)[3]
		array = [@vn, @cd, @dstport, ip, @userid]
		return array.pack('C1C1n1A4A*')
	end
end

class SocksReply
	attr_reader :vn, :cd, :dstport, :dstip

	def initialize vn=nil, cd=nil, dstport=nil, dstip=nil
		@vn = vn
		@cd = cd
		@dstport = dstport
		@dstip = dstip
	end

	def pack
		array = Array.new
		array.push @vn
		array.push @cd
		array.push @dstport
		@dstip.split('.').each {|i| array.push i.to_i}
		return array.pack('C1C1n1C4')
	end
	
	def unpack input
		array = input.unpack('C1C1n1C4')
		@vn = array[0]
		@cd = array[1]
		@dstport = array[2]
		@dstip = array[3].to_s + '.' + array[4].to_s + '.' + array[5].to_s + '.' + array[6].to_s
	end
end

class Rule
	attr_accessor :perm, :mode, :srcip, :srcport, :dstip, :dstport
	def initialize line
		array = line.split ' '
		@perm = array[0]
		@mode = array[1]
		@srcip = array[2]
		@srcport = array[3]
		@dstip = array[4]
		@dstport = array[5]
	end
end

class Firewall
	def self.auth request
		# load firewall config
		@rules = Array.new
		conf = File.new 'socks.conf'
		conf.each {|line|
			next if line =~ /^#/ || line.chomp.empty?
			@rules.push Rule.new line
		}
		# match rules
		@rules.each{|rule|
			# mode
			matchMode = request.cd==1 ? 'c' : 'b'
			next if rule.mode!='-' && rule.mode!=matchMode
			# src ip
			if rule.srcip!='-' then
				patternIP = rule.srcip.split '.'
				matchIP = request.srcip.split '.'
				next if patternIP[0]!='-' && patternIP[0]!=matchIP[0]
				next if patternIP[1]!='-' && patternIP[1]!=matchIP[1]
				next if patternIP[2]!='-' && patternIP[2]!=matchIP[2]
				next if patternIP[3]!='-' && patternIP[3]!=matchIP[3]
			end
			# src port
			next if rule.srcport!='-' && request.srcport.to_s!=rule.srcport
			# dst ip
			if rule.dstip!='-' then
				patternIP = rule.dstip.split '.'
				matchIP = request.dstip.split '.'
				next if patternIP[0]!='-' && patternIP[0]!=matchIP[0]
				next if patternIP[1]!='-' && patternIP[1]!=matchIP[1]
				next if patternIP[2]!='-' && patternIP[2]!=matchIP[2]
				next if patternIP[3]!='-' && patternIP[3]!=matchIP[3]
			end
			# dst port
			next if rule.dstport!='-' && request.dstport.to_s!=rule.dstport
			# all match
			return rule.perm=='permit' ? true : false
		}
		# defult deny
		return false
	end
end
