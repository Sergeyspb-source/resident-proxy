//go:build windows

package main

import "syscall"

// GPT: без этого русские сообщения в cmd.exe выглядят как мусор —
// консоль Windows по умолчанию не в UTF-8.
func initConsole() {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	if p := k32.NewProc("SetConsoleOutputCP"); p.Find() == nil {
		_, _, _ = p.Call(65001)
	}
	if p := k32.NewProc("SetConsoleCP"); p.Find() == nil {
		_, _, _ = p.Call(65001)
	}
}
