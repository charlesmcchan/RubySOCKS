#!/usr/bin/env ruby
require 'socket'
require 'socks.rb'
require 'util.rb'

class SocksServer
	def initialize port
		sockfd = TCPServer.new port
		Debug.info 'Server started, listening on port ' + ARGV[0]
		while true
			begin
				connfd = sockfd.accept_nonblock
			rescue Errno::EAGAIN, Errno::ECONNABORTED, Errno::EPROTO, Errno::EINTR
				IO.select [sockfd]
				retry
			end
			# zombie-free double fork
			Process.fork do
				Process.fork do
					child connfd
				end
				exit 0
			end
			connfd.close
			Process.wait
		end
	end

	def child connfd
		ip = connfd.peeraddr[3]
		port = connfd.peeraddr[1]
		# get SocksRequest
		IO.select [connfd]
		input = Util.readall connfd
		request = SocksRequest.new(nil, nil, nil, nil, nil, port, ip)
		request.unpack input
		Debug.info request.inspect
		connect(connfd, request) if request.cd == 1
		bind(connfd, request) if request.cd == 2
	end

	def connect connfd, request
		# connect to dst ip 
		begin
			proxyfd = TCPSocket.new(request.dstip, request.dstport)
		rescue
			Debug.err $!	
			exit -1
		end
		# generate SocksReply
		cd = (Firewall.auth request) ? 90 : 91
		reply = SocksReply.new(0, cd, request.dstport, request.dstip) 
		connfd.write reply.pack
		Debug.info reply.inspect
		exit -1 if reply.cd == 91
		# tunnel
		tunnel(connfd, proxyfd)
	end

	def bind connfd, request
		# bind a port first
		begin
			srand
			bindport = 7000 + rand(1000)
			sockfd = TCPServer.new bindport 
		rescue Errno::EADDRINUSE
			retry
		end
		# generate SocksReply
		cd = (Firewall.auth request) ? 90 : 91
		myIP = IPSocket.getaddress Socket.gethostname
		reply = SocksReply.new(0, cd, bindport, myIP)
		connfd.write reply.pack
		Debug.info reply.inspect
		exit -1 if reply.cd == 91
		# accept it
		begin
			proxyfd = sockfd.accept_nonblock
		rescue Errno::EAGAIN, Errno::ECONNABORTED, Errno::EPROTO, Errno::EINTR
			IO.select [sockfd]
			retry
		end
		# bind port accept only once
		sockfd.close
		# SocksReply again
		Debug.info reply.inspect
		connfd.write reply.pack
		# tunnel
		tunnel(connfd, proxyfd)	
	end

	def tunnel connfd, proxyfd
		# for content debugging
		dstdata = String.new
		srcdata = String.new
		dstgo = true
		srcgo = true
		# redirect all packets
		while true
			resource = IO.select [connfd, proxyfd]
			for sock in resource[0]
				buf = Util.readone sock
				# write all to the other one
				# log first line 
				# rescue for connfd or proxyfd close
				begin
					if sock == connfd then
						proxyfd.write buf
						srcdata += buf if srcgo
						if buf == "\n" && srcgo then
							Debug.srcdata srcdata
							srcgo = false
						end
					elsif sock == proxyfd then
						connfd.write buf
						dstdata += buf if dstgo
						if buf == "\n" && dstgo then
							Debug.dstdata dstdata
							dstgo = false
						end
					end
				rescue
					Debug.warn $!
					exit -1
				end
			end
		end
	end
end # SocksServer

# main
if ARGV.size < 1 then
	puts 'usage: ' + __FILE__ + ' <port>'
	exit -1
end
Signal.trap("INT") { exit -1 }
Signal.trap("TERM") { exit -1 }
SocksServer.new ARGV[0].to_i
