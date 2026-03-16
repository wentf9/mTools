package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
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

func (m Model) initForm(nodeID string) Model {
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
			state.alias = node.Alias[0]
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
			huh.NewInput().
				Title("Alias (Name of the node)").
				Value(&state.alias),
			huh.NewInput().
				Title("User").
				Value(&state.user).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("user is required")
					}
					return nil
				}),
			huh.NewInput().
				Title("Host Address").
				Value(&state.address).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("address is required")
					}
					return nil
				}),
			huh.NewInput().
				Title("Port").
				Value(&state.port).
				Validate(func(s string) error {
					if _, err := strconv.Atoi(s); err != nil {
						return fmt.Errorf("invalid port, must be number")
					}
					return nil
				}),
		),
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Auth Type").
				Options(
					huh.NewOption("Password", "password"),
					huh.NewOption("Key File", "key"),
				).
				Value(&state.authType),
			huh.NewInput().
				Title("Password").
				EchoMode(huh.EchoModePassword).
				Value(&state.password),
			huh.NewInput().
				Title("Key File Path").
				Value(&state.keyPath),
			huh.NewInput().
				Title("Key Passphrase").
				EchoMode(huh.EchoModePassword).
				Value(&state.passphrase),
		),
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Sudo Mode").
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
				Title("Tags (comma separated)").
				Value(&state.tags),
		),
	)
	m.form.Init()
	return m
}

func (m Model) updateForm(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "esc" {
			// cancel
			m.state = viewList
			return m, nil
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
		return m, nil
	}

	return m, cmd
}

func (m Model) saveForm() {
	s := m.formState

	port, _ := strconv.Atoi(s.port)

	// Save Identity
	identityID := fmt.Sprintf("%s@%s", s.user, s.address)
	identity := models.Identity{
		User:       s.user,
		AuthType:   s.authType,
		Password:   s.password,
		KeyPath:    s.keyPath,
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
	}
	if s.alias != "" {
		node.Alias = []string{s.alias}
	}

	// Delete old node if ID changed or just updating
	if s.isEdit && s.originalID != nodeID {
		m.provider.DeleteNode(s.originalID)
	}
	m.provider.AddNode(nodeID, node)

	_ = m.configStore.Save(m.provider.GetConfig())
}
