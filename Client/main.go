package main

import (
	"os"
	"runtime"

	"GYscan/internal/cli"
	"GYscan/internal/config"
	"GYscan/internal/utils"
)

func main() {
	setupEncoding()
	setupRuntime()

	if err := config.InitConfig(); err != nil {
		utils.LogWarning("配置加载失败，使用默认配置: %v", err)
	}
	os.Setenv("SSL_CERT_FILE", "/data/data/com.termux/files/usr/etc/tls/cert.pem")
	cli.Execute()
}

func setupEncoding() {
	if runtime.GOOS == "windows" {
		os.Setenv("PYTHONIOENCODING", "utf-8")
	}
}

func setupRuntime() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
