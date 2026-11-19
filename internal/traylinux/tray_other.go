//go:build !linux

package traylinux

import (
	"errors"
	"log"
)

// Run на других системах ничего не делает: там свой оконный клиент.
func Run(_ Options, _ *log.Logger) (func(), error) {
	return nil, errors.New("трей доступен только в Linux")
}

// Icon на других системах пустая.
func Icon() []byte { return nil }
