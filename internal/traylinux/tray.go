// Package traylinux показывает иконку клиента в области уведомлений Linux.
// GPT: добавлено, чтобы у клиента на Linux был видимый значок и меню,
// без CGO и без зависимостей от GTK/AppIndicator.
package traylinux

// Options — что показывает и делает иконка.
type Options struct {
	Title   string
	Open    func()
	Running func() bool
	Toggle  func()
}
