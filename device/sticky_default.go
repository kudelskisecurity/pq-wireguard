// +build !linux android

package device

import (
	"github.com/PizzaWhisperer/wireguard/conn"
	"github.com/PizzaWhisperer/wireguard/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
