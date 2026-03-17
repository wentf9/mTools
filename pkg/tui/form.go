package tui

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
)

type nodeFormState struct {
	isEdit     bool
	originalID string

	alias      string
	user       string
	address    string
	port       string
	authType   string
	password   string
	keyPath    string
	passphrase string
	sudoMode   string
	tags       string
}

func (m *Model) initForm(nodeID string) Model {
	state := &nodeFormState{
		port:     "22",
		authType: "password",
		sudoMode: string(models.SudoModeAuto),
	}

	if nodeID != "" {
		state.isEdit = true
		state.originalID = nodeID
		node, _ := m.provider.GetNode(nodeID)
		host, _ := m.provider.GetHost(nodeID)
		identity, _ := m.provider.GetIdentity(nodeID)

		if len(node.Alias) > 0 {
			state.alias = strings.Join(node.Alias, ",")
		}
		state.user = identity.User
		state.address = host.Address
		state.port = strconv.Itoa(int(host.Port))
		if identity.AuthType != "" {
			state.authType = identity.AuthType
		} else if identity.KeyPath != "" {
			state.authType = "key"
		}
		state.password = identity.Password
		state.keyPath = identity.KeyPath
		state.passphrase = identity.Passphrase
		state.sudoMode = string(node.SudoMode)
		if state.sudoMode == "" {
			state.sudoMode = string(models.SudoModeAuto)
		}
		state.tags = strings.Join(node.Tags, ",")
	}

	m.formState = state

	m.form = huh.NewForm(
		huh.NewGroup(
			// 基本信息
			huh.NewInput().
				Title(i18n.T("tui_form_alias")).
				Value(&state.alias).
				Validate(func(s string) error {
					if s == "" {
						return nil
					}
					// Check for duplicate alias
					if !state.isEdit || s != state.alias {
						if m.provider.Find(s) != "" {
							return errors.New(i18n.T("tui_validation_alias_exists"))
						}
					}
					return nil
				}),
			huh.NewInput().
				Title(i18n.T("tui_form_user")).
				Value(&state.user).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return errors.New(i18n.T("tui_validation_user_required"))
					}
					return nil
				}),
			huh.NewInput().
				Title(i18n.T("tui_form_address")).
				Value(&state.address).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return errors.New(i18n.T("tui_validation_address_required"))
					}
					return nil
				}),
			huh.NewInput().
				Title(i18n.T("tui_form_port")).
				Value(&state.port).
				Validate(func(s string) error {
					if _, err := strconv.Atoi(s); err != nil {
						return errors.New(i18n.T("tui_validation_port_invalid"))
					}
					return nil
				}),
			// 认证信息
			huh.NewSelect[string]().
				Title(i18n.T("tui_form_auth_type")).
				Options(
					huh.NewOption("Password", "password"),
					huh.NewOption("Key File", "key"),
				).
				Value(&state.authType),
			huh.NewInput().
				Title(i18n.T("tui_form_password")).
				EchoMode(huh.EchoModePassword).
				Value(&state.password),
			huh.NewInput().
				Title(i18n.T("tui_form_key_path")).
				Value(&state.keyPath),
			huh.NewInput().
				Title(i18n.T("tui_form_key_pass")).
				EchoMode(huh.EchoModePassword).
				Value(&state.passphrase),
			// 其他设置
			huh.NewSelect[string]().
				Title(i18n.T("tui_form_sudo_mode")).
				Options(
					huh.NewOption("Auto", string(models.SudoModeAuto)),
					huh.NewOption("Sudo", string(models.SudoModeSudo)),
					huh.NewOption("Su", string(models.SudoModeSu)),
					huh.NewOption("Sudoer", string(models.SudoModeSudoer)),
					huh.NewOption("Root", string(models.SudoModeRoot)),
					huh.NewOption("None", string(models.SudoModeNone)),
				).
				Value(&state.sudoMode),
			huh.NewInput().
				Title(i18n.T("tui_form_tags")).
				Value(&state.tags),
		),
	).WithTheme(huh.ThemeCharm()).WithWidth(m.lastSize.Width).WithHeight(m.lastSize.Height - 1)
	m.form.Init()
	return *m
}

func (m *Model) updateForm(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if m.form != nil {
			m.form.WithWidth(msg.Width).WithHeight(msg.Height - 1)
		}
		return *m, nil
	case tea.KeyMsg:
		if msg.String() == "esc" {
			// cancel
			m.state = viewList
			return *m, nil
		}
	}

	form, cmd := m.form.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		m.form = f
	}

	if m.form.State == huh.StateCompleted {
		m.saveForm()
		m.state = viewList
		m.list = newListModel(m.provider) // refresh list
		// 应用窗口大小
		*m, _ = m.updateList(m.lastSize)
		return *m, nil
	}

	return *m, cmd
}

func (m *Model) saveForm() {
	s := m.formState

	port, _ := strconv.Atoi(s.port)

	// Standardize key path
	absKeyPath := ""
	if s.authType == "key" && s.keyPath != "" {
		absKeyPath = utils.ToAbsolutePath(s.keyPath)
	}

	// Save Identity
	identityID := fmt.Sprintf("%s@%s", s.user, s.address)
	identity := models.Identity{
		User:       s.user,
		AuthType:   s.authType,
		Password:   s.password,
		KeyPath:    absKeyPath,
		Passphrase: s.passphrase,
	}
	if s.authType == "password" {
		identity.KeyPath = ""
		identity.Passphrase = ""
	} else {
		identity.Password = ""
	}
	m.provider.AddIdentity(identityID, identity)

	// Save Host
	hostID := fmt.Sprintf("%s:%d", s.address, port)
	host := models.Host{
		Address: s.address,
		Port:    uint16(port),
	}
	m.provider.AddHost(hostID, host)

	// Save Node
	var alias []string
	if strings.TrimSpace(s.alias) != "" {
		for _, a := range strings.Split(s.alias, ",") {
			sa := strings.TrimSpace(a)
			if sa != "" {
				alias = append(alias, sa)
			}
		}
	}

	var tags []string
	if strings.TrimSpace(s.tags) != "" {
		for _, t := range strings.Split(s.tags, ",") {
			st := strings.TrimSpace(t)
			if st != "" {
				tags = append(tags, st)
			}
		}
	}

	nodeID := fmt.Sprintf("%s@%s:%d", s.user, s.address, port)
	node := models.Node{
		HostRef:     hostID,
		IdentityRef: identityID,
		SudoMode:    models.SudoMode(s.sudoMode),
		Tags:        tags,
		Alias:       alias,
	}

	// Delete old node if ID changed or just updating
	if s.isEdit && s.originalID != nodeID {
		m.provider.DeleteNode(s.originalID)
	}
	m.provider.AddNode(nodeID, node)

	err := m.configStore.Save(m.provider.GetConfig())
	if err != nil {
		m.status = errorStyle.Render(i18n.Tf("tui_status_save_failed", map[string]any{"Error": err}))
	} else {
		m.status = successStyle.Render(i18n.Tf("tui_status_saved", map[string]any{"ID": nodeID}))
	}
}
