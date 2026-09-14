function host_ip(desync)
	return desync.target.ip and ntop(desync.target.ip) or desync.target.ip6 and ntop(desync.target.ip6)
end
