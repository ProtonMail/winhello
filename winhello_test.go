//go:build windows

package winhello

import (
	"os"
	"testing"

	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/go-ctap/winhello/window"
	"github.com/goforj/godump"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var (
	hWnd windows.HWND
)

func runWinHelloTests() bool {
	env := os.Getenv("WINHELLO_TESTS")
	return env == "true" || env == "1"
}

func TestMain(m *testing.M) {
	if !runWinHelloTests() {
		m.Run()
	} else {
		wnd, err := window.GetForegroundWindow()
		if err != nil {
			panic(err)
		}

		hWnd = wnd
		m.Run()
	}
}

func TestGetPlatformAssertion(t *testing.T) {
	if !runWinHelloTests() {
		t.Skip("Skipping test because WINHELLO_TESTS is not set")
	}

	assertion, err := GetAssertion(
		hWnd,
		"example.org",
		[]byte("{}"),
		nil,
		nil,
		&AuthenticatorGetAssertionOptions{
			AuthenticatorAttachment:     WinHelloAuthenticatorAttachmentPlatform,
			UserVerificationRequirement: WinHelloUserVerificationRequirementDiscouraged,
			CredentialHints: []webauthntypes.PublicKeyCredentialHint{
				webauthntypes.PublicKeyCredentialHintClientDevice,
				webauthntypes.PublicKeyCredentialHintSecurityKey,
				webauthntypes.PublicKeyCredentialHintHybrid,
			},
		},
	)
	require.NoError(t, err)

	godump.Dump(assertion)
}
