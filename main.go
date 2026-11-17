package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "golang.org/x/crypto/x509roots/fallback" // CA roots when the image has none
	_ "time/tzdata"
)

const Version = "2.4.5"

var (
	AppDir         = "/opt/huboze-ddns-agent"
	DataDir        string
	ConfigDir      string
	DBPath         string
	KnownHostsFile string
	FernetKeyFile  string
	SecretKeyFile  string
)

func initPaths() {
	if v := strings.TrimSpace(os.Getenv("HUBOZE_APP_DIR")); v != "" {
		AppDir = v
	}
	DataDir = filepath.Join(AppDir, "data")
	ConfigDir = filepath.Join(AppDir, "config")
	DBPath = filepath.Join(DataDir, "huboze-ddns.db")
	KnownHostsFile = filepath.Join(DataDir, "known_hosts")
	FernetKeyFile = filepath.Join(ConfigDir, "fernet.key")
	SecretKeyFile = filepath.Join(ConfigDir, "flask_secret.key")
}

// inContainer is true inside the huboze-ddns-agent image (set by the image ENV).
func inContainer() bool { return os.Getenv("HUBOZE_IN_CONTAINER") == "1" }

func usage() {
	fmt.Println(`huboze DDNS Agent v` + Version + `（Go + Docker Compose）

用法: huboze-ddns-agent <命令>

  install                   安装 / 升级（自动检测环境、安装 Docker 与 Compose、迁移旧版本）
  info                      显示部署信息（访问地址、账号、目录、常用命令）
  status                    查看容器状态与健康检查
  logs                      查看实时日志
  start | stop | restart    启动 / 停止 / 重启
  selfcheck                 运行环境自检
  backup                    打包整个程序目录到 /root
  restore <迁移包.tar.gz>    从 Web 下载的迁移包恢复
  reset-password [密码]     重置 Web admin 密码（不带参数则交互输入）
  reset-whitelist           清空 Web 来源 CIDR 白名单（白名单配错被锁在外面时使用）
  version

环境变量: WEB_PORT（默认沿用当前端口，首次安装为 8080）、HUBOZE_APP_DIR（默认 /opt/huboze-ddns-agent）`)
}

func main() {
	log.SetFlags(log.LstdFlags)
	initPaths()
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	// ---- inside the container ----
	case "serve":
		err = serve()
	case "healthcheck":
		err = cmdHealthcheck()
	// ---- host management (each also works inside the container where it makes sense) ----
	case "install":
		err = install()
	case "status":
		err = cmdStatus()
	case "info":
		err = cmdInfo()
	case "logs":
		err = runCmd("docker", "logs", "-f", "--tail", "200", containerName)
	case "start":
		err = composeRun("up", "-d")
	case "stop":
		err = composeRun("stop")
	case "restart":
		err = composeRun("restart")
	case "selfcheck":
		err = cmdSelfCheck()
	case "backup":
		err = cmdBackup()
	case "restore":
		if len(args) < 1 {
			err = exitError{2, "用法：huboze-ddns-agent restore /路径/迁移包.tar.gz"}
			break
		}
		err = cmdRestore(args[0])
	case "reset-password":
		err = cmdResetPassword(args)
	case "reset-whitelist":
		err = cmdResetWhitelist()
	case "version", "--version", "-v":
		fmt.Println(Version)
	default:
		usage()
		os.Exit(1)
	}
	if err != nil {
		var ee exitError
		if errors.As(err, &ee) {
			if ee.msg != "" {
				fmt.Fprintln(os.Stderr, ee.msg)
			}
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "[ERROR]", err)
		os.Exit(1)
	}
}

type exitError struct {
	code int
	msg  string
}

func (e exitError) Error() string { return e.msg }

func webPort() string {
	if p := strings.TrimSpace(os.Getenv("WEB_PORT")); p != "" {
		return p
	}
	return "8080"
}

func serve() error {
	if err := loadKeys(); err != nil {
		return err
	}
	if err := openDB(); err != nil {
		return err
	}
	if err := initDB(); err != nil {
		return fmt.Errorf("初始化数据库失败：%w", err)
	}
	initRuntimeState()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if os.Getenv("ENABLE_POLLER") != "0" {
		go pollerLoop(ctx)
	}
	listen := os.Getenv("LISTEN_ADDR")
	if listen == "" {
		listen = ":" + webPort()
	}
	srv := &http.Server{
		Addr:              listen,
		Handler:           newRouter(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      180 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		log.Printf("huboze DDNS Agent v%s 已启动，监听 %s（数据目录：%s）", Version, listen, DataDir)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	runtimeTick()
	return DB.Close()
}

// cmdHealthcheck is the Docker HEALTHCHECK (the scratch image has no curl).
func cmdHealthcheck() error {
	c := &http.Client{Timeout: 4 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + webPort() + "/health")
	if err != nil {
		return exitError{1, err.Error()}
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return exitError{1, fmt.Sprintf("健康检查失败：HTTP %d", resp.StatusCode)}
	}
	return nil
}

// openForMaintenance opens keys + DB for one-shot commands inside the container.
func openForMaintenance() error {
	if err := loadKeys(); err != nil {
		return err
	}
	if err := openDB(); err != nil {
		return err
	}
	return initDB()
}

func cmdSelfCheck() error {
	if !inContainer() {
		if err := requireRoot(); err != nil {
			return err
		}
		if !containerRunning() {
			return exitError{1, "容器未运行，请先执行：huboze-ddns-agent start"}
		}
		return runCmd("docker", "exec", containerName, "/huboze-ddns-agent", "selfcheck")
	}
	if err := openForMaintenance(); err != nil {
		return err
	}
	defer DB.Close()
	fmt.Println("huboze DDNS Agent v" + Version + " 运行环境自检：")
	_, failAny := printCheckItems(runSelfCheck())
	if failAny {
		return exitError{1, ""}
	}
	return nil
}

func readStdinLine() string {
	s := bufio.NewScanner(os.Stdin)
	if s.Scan() {
		return strings.TrimRight(s.Text(), "\r\n")
	}
	return ""
}

func cmdResetPassword(args []string) error {
	if inContainer() {
		if len(args) == 0 || args[0] != "--stdin" {
			return exitError{2, "容器内请使用：reset-password --stdin"}
		}
		pw := readStdinLine()
		if len([]rune(pw)) < 10 {
			return exitError{2, "密码至少需要 10 个字符"}
		}
		if err := openForMaintenance(); err != nil {
			return err
		}
		defer DB.Close()
		h, err := generatePasswordHash(pw)
		if err != nil {
			return err
		}
		if err := dbExec("UPDATE users SET password_hash=? WHERE username='admin'", h); err != nil {
			return err
		}
		fmt.Println("Web 管理员密码已重置。")
		return nil
	}
	if err := requireRoot(); err != nil {
		return err
	}
	pw := ""
	if len(args) > 0 {
		pw = args[0]
	} else {
		p, err := promptPassword()
		if err != nil {
			return err
		}
		pw = p
	}
	if len([]rune(pw)) < 10 {
		return exitError{2, "密码至少需要 10 个字符"}
	}
	// The password goes through stdin, never through process arguments.
	return containerOneShot(pw+"\n", "reset-password", "--stdin")
}

func cmdResetWhitelist() error {
	if inContainer() {
		if err := openForMaintenance(); err != nil {
			return err
		}
		defer DB.Close()
		setSetting("allowed_web_cidrs", "")
		fmt.Println("Web 来源 CIDR 白名单已清空。")
		return nil
	}
	if err := requireRoot(); err != nil {
		return err
	}
	return containerOneShot("", "reset-whitelist")
}
