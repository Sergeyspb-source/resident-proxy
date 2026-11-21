//go:build linux

package traylinux

import (
	"bytes"
	_ "embed"
	"fmt"
	"image/png"
	"log"
	"os"
	"sync"

	"github.com/godbus/dbus/v5"

	"exitnode/internal/buildinfo"
	"exitnode/internal/versionicon"
	"github.com/godbus/dbus/v5/prop"
)

//go:embed icon.png
var iconPNG []byte

// Icon возвращает PNG-иконку приложения для ярлыка.
func Icon() []byte { return iconPNG }

const (
	sniPath   = dbus.ObjectPath("/StatusNotifierItem")
	menuPath  = dbus.ObjectPath("/MenuBar")
	sniIface  = "org.kde.StatusNotifierItem"
	menuIface = "com.canonical.dbusmenu"

	idOpen   = int32(1)
	idToggle = int32(2)
	idSep    = int32(3)
	idQuit   = int32(4)
)

type item struct {
	conn *dbus.Conn
	name string
	opts Options
}

func (i *item) Activate(x, y int32) *dbus.Error                    { i.do(i.opts.Open); return nil }
func (i *item) SecondaryActivate(x, y int32) *dbus.Error           { i.do(i.opts.Open); return nil }
func (i *item) ContextMenu(x, y int32) *dbus.Error                 { return nil }
func (i *item) Scroll(delta int32, orientation string) *dbus.Error { return nil }

func (i *item) do(fn func()) {
	if fn != nil {
		fn()
	}
}

type layout struct {
	ID       int32
	Props    map[string]dbus.Variant
	Children []dbus.Variant
}

type propEntry struct {
	ID    int32
	Props map[string]dbus.Variant
}

type menu struct {
	item     *item
	mu       sync.Mutex
	revision uint32
}

func (m *menu) leaf(id int32, label string) layout {
	return layout{ID: id, Props: map[string]dbus.Variant{
		"label":   dbus.MakeVariant(label),
		"enabled": dbus.MakeVariant(true),
		"visible": dbus.MakeVariant(true),
	}}
}

func (m *menu) toggleLabel() string {
	if m.item.opts.Running != nil && m.item.opts.Running() {
		return "РћСЃС‚Р°РЅРѕРІРёС‚СЊ"
	}
	return "Р—Р°РїСѓСЃС‚РёС‚СЊ"
}

func (m *menu) tree() layout {
	sep := layout{ID: idSep, Props: map[string]dbus.Variant{
		"type":    dbus.MakeVariant("separator"),
		"visible": dbus.MakeVariant(true),
	}}
	return layout{ID: 0, Props: map[string]dbus.Variant{}, Children: []dbus.Variant{
		dbus.MakeVariant(m.leaf(idOpen, "РћС‚РєСЂС‹С‚СЊ РїР°РЅРµР»СЊ")),
		dbus.MakeVariant(m.leaf(idToggle, m.toggleLabel())),
		dbus.MakeVariant(sep),
		dbus.MakeVariant(m.leaf(idQuit, "Р’С‹С…РѕРґ")),
	}}
}

func (m *menu) GetLayout(parent int32, depth int32, names []string) (uint32, layout, *dbus.Error) {
	m.mu.Lock()
	rev := m.revision
	m.mu.Unlock()
	if parent != 0 {
		return rev, layout{ID: parent}, nil
	}
	return rev, m.tree(), nil
}

func (m *menu) GetGroupProperties(ids []int32, names []string) ([]propEntry, *dbus.Error) {
	tree := m.tree()
	out := []propEntry{{ID: 0, Props: tree.Props}}
	for _, v := range tree.Children {
		child, ok := v.Value().(layout)
		if !ok {
			continue
		}
		out = append(out, propEntry{ID: child.ID, Props: child.Props})
	}
	return out, nil
}

func (m *menu) GetProperty(id int32, name string) (dbus.Variant, *dbus.Error) {
	for _, v := range m.tree().Children {
		child, ok := v.Value().(layout)
		if ok && child.ID == id {
			if val, ok := child.Props[name]; ok {
				return val, nil
			}
		}
	}
	return dbus.MakeVariant(""), nil
}

func (m *menu) AboutToShow(id int32) (bool, *dbus.Error) { return false, nil }

func (m *menu) Event(id int32, eventID string, data dbus.Variant, ts uint32) *dbus.Error {
	if eventID != "clicked" {
		return nil
	}
	switch id {
	case idOpen:
		m.item.do(m.item.opts.Open)
	case idToggle:
		m.item.do(m.item.opts.Toggle)
		m.bump()
	case idQuit:
		os.Exit(0)
	}
	return nil
}

func (m *menu) bump() {
	m.mu.Lock()
	m.revision++
	rev := m.revision
	m.mu.Unlock()
	_ = m.item.conn.Emit(menuPath, menuIface+".LayoutUpdated", rev, int32(0))
}

type pixmap struct {
	Width  int32
	Height int32
	Data   []byte
}

// GPT: Add the current build badge to the existing Linux tray image.
func iconPixmaps() []pixmap {
	img, err := png.Decode(bytes.NewReader(iconPNG))
	if err != nil {
		return nil
	}
	img = versionicon.Badge(img, buildinfo.Version)
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	data := make([]byte, w*h*4)
	pos := 0
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bb, a := img.At(x, y).RGBA()
			data[pos] = byte(a >> 8)
			data[pos+1] = byte(r >> 8)
			data[pos+2] = byte(g >> 8)
			data[pos+3] = byte(bb >> 8)
			pos += 4
		}
	}
	return []pixmap{{Width: int32(w), Height: int32(h), Data: data}}
}

// Run СЂРµРіРёСЃС‚СЂРёСЂСѓРµС‚ РёРєРѕРЅРєСѓ Рё РјРµРЅСЋ. Р’РѕР·РІСЂР°С‰Р°РµС‚ С„СѓРЅРєС†РёСЋ РѕСЃС‚Р°РЅРѕРІРєРё.
func Run(opts Options, logger *log.Logger) (func(), error) {
	opts.Title += " v" + buildinfo.Version
	if logger == nil {
		logger = log.Default()
	}
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, err
	}

	name := fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", os.Getpid())
	reply, err := conn.RequestName(name, dbus.NameFlagDoNotQueue)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		_ = conn.Close()
		return nil, fmt.Errorf("РёРјСЏ %s СѓР¶Рµ Р·Р°РЅСЏС‚Рѕ", name)
	}

	it := &item{conn: conn, name: name, opts: opts}
	m := &menu{item: it, revision: 1}

	if err := conn.Export(it, sniPath, sniIface); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.Export(m, menuPath, menuIface); err != nil {
		_ = conn.Close()
		return nil, err
	}

	spec := prop.Map{
		sniIface: {
			"Category":   {Value: "ApplicationStatus"},
			"Id":         {Value: "exitnode"},
			"Title":      {Value: opts.Title},
			"Status":     {Value: "Active"},
			"IconName":   {Value: ""},
			"IconPixmap": {Value: iconPixmaps()},
			"ItemIsMenu": {Value: false},
			"Menu":       {Value: menuPath},
		},
	}
	if _, err := prop.Export(conn, sniPath, spec); err != nil {
		_ = conn.Close()
		return nil, err
	}

	menuSpec := prop.Map{
		menuIface: {
			"Version":       {Value: uint32(3)},
			"TextDirection": {Value: "ltr"},
			"Status":        {Value: "normal"},
			"IconThemePath": {Value: []string{}},
		},
	}
	if _, err := prop.Export(conn, menuPath, menuSpec); err != nil {
		_ = conn.Close()
		return nil, err
	}

	watcher := conn.Object("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher")
	if err := watcher.Call("org.kde.StatusNotifierWatcher.RegisterStatusNotifierItem", 0, name).Err; err != nil {
		logger.Printf("С‚СЂРµР№: РЅРµС‚ StatusNotifierWatcher: %v", err)
	}

	logger.Printf("С‚СЂРµР№: РёРєРѕРЅРєР° Р·Р°СЂРµРіРёСЃС‚СЂРёСЂРѕРІР°РЅР° (%s)", name)
	return func() {
		_, _ = conn.ReleaseName(name)
		_ = conn.Close()
	}, nil
}
