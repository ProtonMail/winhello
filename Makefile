.PHONY: init-extern rm-extern reinit-extern make-types

init-extern:
	git submodule init
	git submodule update --recursive

rm-extern:
	git submodule deinit extern/webauthnwin
	git rm extern/webauthnwin
	rm -rf .git/modules/extern/webauthnwin

reinit-extern: rm-extern
	git submodule add https://github.com/microsoft/webauthn.git extern/webauthnwin
	git submodule init
	git submodule update --recursive

make-types:
	go tool cgo -godefs types_webauthn.go | Out-File -Encoding utf8 ztypes_webauthn.go
