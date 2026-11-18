//go:build !windows && !linux

package setup

import "errors"

func Install(Options) (string, error) {
	return "", errors.New("установщик доступен только в Windows")
}

func FinishUninstall() {}
func Message(string)   {}
