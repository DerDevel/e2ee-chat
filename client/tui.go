package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4")).MarginBottom(1)
	nickStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("201")).Bold(true)
	selfStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	errorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	systemStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true)
	cursorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Blink(true)
)

type chatMsg struct{ nick, text string }
type systemMsg struct{ text string }
type errorMsg struct{ text string }
type tickMsg struct{}

func tick() tea.Cmd {
	return tea.Tick(time.Millisecond*500, func(time.Time) tea.Msg {
		return tickMsg{}
	})
}

type model struct {
	state    string
	nickname string
	keyword  string
	input    string
	messages []string
	spinner  spinner.Model
	blink    bool
	width    int
	height   int
	cmdCh    chan string
}

func initialModel(cmdCh chan string) model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("212"))
	return model{
		state:    "setup_nick",
		messages: []string{},
		spinner:  s,
		cmdCh:    cmdCh,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, tick())
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		m.blink = !m.blink
		return m, tick()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case systemMsg:
		// ОБРАБОТКА ОТКЛЮЧЕНИЙ
		if msg.text == "PEER_LEFT" || msg.text == "SERVER_DISCONNECTED" {
			fmt.Print("\a")         // Звук
			m.messages = []string{} // Очистка истории
			m.state = "setup_room"  // Возврат в меню
			if msg.text == "PEER_LEFT" {
				m.messages = append(m.messages, systemStyle.Render("* Собеседник отключился."))
			} else {
				m.messages = append(m.messages, errorStyle.Render("* Соединение с сервером потеряно."))
			}
			m.messages = append(m.messages, systemStyle.Render("* Введите новое кодовое слово (или /join <слово>):"))
			return m, nil
		}

		m.messages = append(m.messages, systemStyle.Render("* "+msg.text))
		if msg.text == "REQUEST_INCOMING" {
			fmt.Print("\a")
			m.state = "request"
		} else if msg.text == "CONNECTED" {
			m.state = "chat"
		} else if strings.Contains(msg.text, "не найдена") || strings.Contains(msg.text, "разорвано") || strings.Contains(msg.text, "отклонен") {
			m.state = "setup_room"
		}

	case chatMsg:
		fmt.Print("\a")
		m.messages = append(m.messages, fmt.Sprintf("[%s]: %s", nickStyle.Render(msg.nick), msg.text))

	case errorMsg:
		m.messages = append(m.messages, errorStyle.Render("[ERROR] "+msg.text))
		// Если комната занята, возвращаемся к вводу
		if strings.Contains(msg.text, "занята") {
			m.state = "setup_room"
		}

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			return m, tea.Quit
		case tea.KeyEnter:
			cmd := m.handleEnter()
			if cmd != "" {
				m.cmdCh <- cmd
			}
			m.input = ""
		case tea.KeyBackspace:
			if len(m.input) > 0 {
				m.input = m.input[:len(m.input)-1]
			}
		case tea.KeyRunes:
			m.input += string(msg.Runes)
		case tea.KeySpace:
			m.input += " "
		}
	}
	return m, nil
}

func (m *model) handleEnter() string {
	switch m.state {
	case "setup_nick":
		m.nickname = m.input
		m.state = "setup_room"
		m.messages = append(m.messages, systemStyle.Render("* Никнейм установлен: "+m.nickname))
		return "nick:" + m.nickname
	case "setup_room":
		if strings.HasPrefix(m.input, "/join ") {
			m.keyword = strings.TrimPrefix(m.input, "/join ")
			m.state = "waiting"
			m.messages = append(m.messages, systemStyle.Render("* Поиск комнаты "+m.keyword+"..."))
			return "find:" + m.keyword
		}
		m.keyword = m.input
		m.state = "waiting"
		m.messages = append(m.messages, systemStyle.Render("* Ожидание подключения по ключу "+m.keyword+"..."))
		return "register:" + m.keyword
	case "request":
		if m.input == "y" || m.input == "Y" {
			m.state = "waiting"
			m.messages = append(m.messages, systemStyle.Render("* Запрос принят. Установка соединения..."))
			return "accept"
		}
		m.state = "setup_room"
		m.messages = append(m.messages, systemStyle.Render("* Запрос отклонен."))
		return "reject"
	case "chat":
		if m.input != "" {
			m.messages = append(m.messages, fmt.Sprintf("[%s]: %s", selfStyle.Render(m.nickname), m.input))
			return "msg:" + m.input
		}
	}
	return ""
}

func (m model) View() string {
	if m.width == 0 {
		return "Загрузка..."
	}

	var s strings.Builder
	s.WriteString(titleStyle.Render(" 🔒 E2E Encrypted Console Chat "))
	s.WriteString("\n\n")

	chatHeight := m.height - 7
	if chatHeight < 1 {
		chatHeight = 1
	}

	start := 0
	if len(m.messages) > chatHeight {
		start = len(m.messages) - chatHeight
	}
	visibleMsgs := m.messages[start:]

	for _, msg := range visibleMsgs {
		s.WriteString(msg + "\n")
	}

	linesUsed := 2 + len(visibleMsgs)
	padding := m.height - linesUsed - 4
	if padding > 0 {
		s.WriteString(strings.Repeat("\n", padding))
	}

	cursorChar := " "
	if m.blink {
		cursorChar = "█"
	}

	switch m.state {
	case "setup_nick":
		s.WriteString("Введите никнейм: ")
		s.WriteString(m.input)
		s.WriteString(cursorStyle.Render(cursorChar))
	case "setup_room":
		s.WriteString("Кодовое слово (или /join <слово>): ")
		s.WriteString(m.input)
		s.WriteString(cursorStyle.Render(cursorChar))
	case "waiting":
		s.WriteString(m.spinner.View() + " ")
		s.WriteString(systemStyle.Render("Ожидание... (Ctrl+C для выхода)"))
	case "request":
		s.WriteString(errorStyle.Render("Разрешить подключение? (y/n): "))
		s.WriteString(m.input)
		s.WriteString(cursorStyle.Render(cursorChar))
	case "chat":
		s.WriteString(selfStyle.Render("[" + m.nickname + "] > "))
		s.WriteString(m.input)
		s.WriteString(cursorStyle.Render(cursorChar))
	}

	s.WriteString("\n\n")
	s.WriteString(systemStyle.Render("Нажмите Ctrl+C для выхода."))
	return s.String()
}
