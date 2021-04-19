// +build !linux android

package device

import (
	"github.com/kudelskisecurity/wireguard/conn"
	"github.com/kudelskisecurity/wireguard/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
