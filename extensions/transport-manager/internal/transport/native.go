package transport

import (
	"context"
	"net"
	"time"
)

type Native struct{ tag, iface string }

func NewNative(tag, iface string) *Native    { return &Native{tag: tag, iface: iface} }
func (n *Native) Tag() string                { return n.tag }
func (n *Native) Up(context.Context) error   { return nil }
func (n *Native) Down(context.Context) error { return nil }
func (n *Native) Status(context.Context) Status {
	state := StateDown
	var message string
	if _, err := net.InterfaceByName(n.iface); err == nil {
		state = StateUp
	} else {
		message = err.Error()
	}
	return Status{Tag: n.tag, Type: "native", Interface: n.iface, State: state, Error: message, UpdatedAt: time.Now().UTC()}
}
