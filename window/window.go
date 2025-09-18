//go:build windows

package window

import (
	_ "embed"
	"golang.org/x/sys/windows"
	"syscall"
)

var (
	user32                  = syscall.NewLazyDLL("user32.dll")
	procGetForegroundWindow = user32.NewProc("GetForegroundWindow")
)

func GetForegroundWindow() (windows.HWND, error) {
	ret, _, err := procGetForegroundWindow.Call()
	if ret == 0 {
		return 0, err
	}
	return windows.HWND(ret), nil
}
