package model

type Host struct {
	Alias     string   `yaml:"alias"`      // 别名
	HostNames []string `yaml:"host_names"` // 主机名/ip/域名
	Port      uint16   `yaml:"port"`       // 端口
	AuthName  string   `yaml:"auth_name"`  // 认证配置
}

type HostsGroup struct {
	Name  string   `yaml:"name"`  // 组名
	Hosts []string `yaml:"hosts"` // 主机列表
}

type AuthConfig struct {
	Name           string `yaml:"name"`             // 别名
	Comment        string `yaml:"comment"`          // 备注
	User           string `yaml:"user"`             // 用户名
	PrivateKeyPath string `yaml:"private_key_path"` // 私钥路径
	Passphrase     string `yaml:"passphrase"`       // 私钥密码
	Pwd            string `yaml:"pwd"`              // 登录密码
	SuPwd          string `yaml:"su_pwd"`           // root密码
	/* 提权类型:
		no-已经是root用户,无需提权;
	 	sudoer-使用sudo命令提权,但用户在sudoers文件中无需密码;
		sudo-使用带密码的sudo提权,依赖pwd;
	 	su-使用su root切换到root用户,依赖suPwd;
	*/
	SuType string `yaml:"su_type"`
}
