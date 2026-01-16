package sshclient

type SSHInfo struct {
	Host string   // SSH主机地址
	Port uint16   // SSH端口
	Auth AuthInfo // 认证信息
}

type AuthInfo struct {
	User    string // 登录用户
	Pwd     string // 登录密码
	SuPwd   string // root密码
	keyPath string // SSH私钥路径
	/* 提权类型:
		no-已经是root用户,无需提权;
	 	sudoer-使用sudo命令提权,但用户在sudoers文件中无需密码;
		sudo-使用带密码的sudo提权,依赖pwd;
	 	su-使用su root切换到root用户,依赖suPwd;
	*/
	SuType string
}
