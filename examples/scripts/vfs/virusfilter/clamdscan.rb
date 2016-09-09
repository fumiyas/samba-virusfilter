#!/usr/bin/env ruby

require 'socket'

def clamd_socket()
  socket = UNIXSocket.open("/var/run/clamav/clamd.ctl")
  return socket
end

def clamd_command(socket, command=nil)
  if command != nil
    print "-> #{command}"
    socket.write(command)
  end
  reply = socket.readline
  print "<- #{reply}"
end

def clamd_scan(socket, file)
  clamd_command(socket, "SCAN #{file}\n")
end

if ARGV.size != 1
  print "Usage: $0 FILE\n";
  exit 1
end

file = ARGV.shift

socket = clamd_socket
clamd_scan(socket, file)
exit(0)

