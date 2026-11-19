//go:build !windows

// Пакет sysproxy на других системах ничего не меняет.
package sysproxy

import "errors"

func Supported() bool { return false }

func Enable(_ string) error { return errors.New("системный прокси доступен только в Windows") }

func Disable() error { return nil }

func Enabled() bool { return false }

func RestoreIfLeftover() {}
