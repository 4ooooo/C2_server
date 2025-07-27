在windows上编译linux可执行文件命令
```
$orig_cgo=$env:CGO_ENABLED;$orig_goos=$env:GOOS;$orig_goarch=$env:GOARCH;$env:CGO_ENABLED=0;$env:GOOS="linux";$env:GOARCH="amd64";go build -o c2_server_linux;$env:CGO_ENABLED=$orig_cgo;$env:GOOS=$orig_goos;$env:GOARCH=$orig_goarch;Remove-Variable orig_cgo,orig_goos,orig_goarch
```