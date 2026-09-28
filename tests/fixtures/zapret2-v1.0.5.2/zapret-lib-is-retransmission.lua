function is_retransmission(desync)
	return desync.track and desync.track.pos.direct.tcp and seq_ge(desync.track.pos.direct.tcp.uppos_prev, desync.track.pos.direct.tcp.pos)
end
