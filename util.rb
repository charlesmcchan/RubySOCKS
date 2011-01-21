#!/usr/bin/env ruby

class Debug
	# switch of debug mode
	DEBUG = false

	def self.info msg
		puts "\033[32m[I]\033[m " + msg if DEBUG
	end
	def self.warn msg
		puts "\033[33m[W]\033[m " + msg if DEBUG
	end
	def self.err msg
		puts "\033[31m[E]\033[m " + msg if DEBUG
	end
	def self.srcdata msg
		puts "\033[36m[>]\033[m " + msg if DEBUG
	end
	def self.dstdata msg
		puts "\033[36m[<]\033[m " + msg if DEBUG
	end
end

class Util
	# read until EAGAIN
	def self.readall connfd
		input = String.new
		while true
			begin
				input += connfd.read_nonblock 10485760
			# no more to read
			rescue Errno::EAGAIN
				return input
			# connection close
			rescue 
				Debug.warn $!
				exit 0
			end
		end
	end
	
	# read byte by byte	
	def self.readone connfd
		begin
			buf = connfd.read_nonblock 10485760
			# no more to read
		rescue Errno::EAGAIN
			return buf
			# connection close
		rescue
			Debug.warn $!
			exit 0
		end
	end
end
