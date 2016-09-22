#!/usr/bin/env ruby

require 'socket'
require "benchmark"

def fsav_socket()
  socket = UNIXSocket.open("/tmp/.fsav-0")
  fsav_command(socket, nil, false)

  fsav_command(socket, "PROTOCOL\t5\n")
  fsav_command(socket, "CONFIGURE\tARCHIVE\t1\n")
  fsav_command(socket, "CONFIGURE\tMAXARCH\t2\n")
  fsav_command(socket, "CONFIGURE\tMIME\t1\n")
  fsav_command(socket, "CONFIGURE\tRISKWARE\t1\n")
  fsav_command(socket, "CONFIGURE\tFILTER\t0\n")

  return socket
end

def fsav_command(socket, command=nil, all=true)
  if command != nil
    print "-> #{command}"
    socket.write(command)
  end
  loop do
    reply = socket.readline
    print "<- #{reply}"
    break if !all || reply =~ /^(OK|ERROR)\t/
  end
end

def fsav_scan(socket, file)
  fsav_command(socket, "SCAN\t#{file}\n")
end

if ARGV.size != 1
  print "Usage: $0 FILE\n";
  exit 1
end

file = ARGV.shift

socket = fsav_socket
fsav_command(socket, "STATUS\n")
fsav_command(socket, "PING\n")
fsav_scan(socket, file)
exit(0)

n=5000

Benchmark.bm(10) do |x|
  x.report("One socket per benchmark") do
    socket = fsav_socket
    n.times do
      fsav_scan(socket, file)
    end
  end
  x.report("One socket per scan") do
    n.times do
      socket = fsav_socket
      fsav_scan(socket, file)
    end
  end
end

