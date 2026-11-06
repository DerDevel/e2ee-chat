package main

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const maxHistory = 500

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4")).MarginBottom(1)
	nickStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("201")).Bold(true)
	selfStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	errorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	systemStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true)
	cursorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Blink(true)
)

const helpText = `Доступные команды:
  /join <слово>  — подключиться к комнате по кодовому слову
  /nick <имя>    — сменить никнейм
  /help          — показать эту справку
  /quit          — выход (также Ctrl+C)`

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

// add appends a rendered line to the history, keeping the buffer bounded.
func (m *model) add(line string) {
	m.messages = append(m.messages, line)
	if excess := len(m.messages) - maxHistory; excess > 0 {
		m.messages = m.messages[excess:]
	}
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
		switch msg.text {
		case "PEER_LEFT", "SERVER_DISCONNECTED":
			fmt.Print("\a")         // Звук
			m.messages = []string{} // Очистка истории
			if msg.text == "PEER_LEFT" {
				m.state = "setup_room" // Возврат в меню
				m.add(systemStyle.Render("* Собеседник отключился."))
				m.add(systemStyle.Render("* Введите новое кодовое слово (или /join <слово>):"))
			} else {
				m.state = "dead"
				m.add(errorStyle.Render("* Соединение с сервером потеряно. Перезапустите клиент."))
			}
			return m, nil
		case "PEER_REJECTED":
			m.add(systemStyle.Render("* Собеседник отклонил запрос."))
			m.state = "setup_room"
		case "REQUEST_INCOMING":
			// Only a client that is actually waiting to pair may be pushed
			// into the accept prompt; mid-chat the relay must not be able to
			// hijack keystrokes (SEC-007).
			switch m.state {
			case "waiting", "setup_room", "request":
				fmt.Print("\a")
				m.state = "request"
			default:
				m.add(systemStyle.Render("* Входящий запрос проигнорирован (активен другой чат)."))
			}
		case "HANDSHAKE_WAIT":
			m.state = "waiting_handshake"
		case "CONNECTED":
			m.state = "chat"
		default:
			m.add(systemStyle.Render("* " + msg.text))
		}

	case chatMsg:
		fmt.Print("\a")
		m.add(fmt.Sprintf("[%s]: %s", nickStyle.Render(msg.nick), msg.text))

	case errorMsg:
		m.add(errorStyle.Render("[ERROR] " + msg.text))
		// Ошибки на этапе ожидания возвращают к вводу кодового слова.
		if m.state == "waiting" || m.state == "waiting_handshake" || m.state == "request" {
			m.state = "setup_room"
		}

	case tea.KeyMsg:
		if m.state == "dead" {
			return m, nil // соединения нет — ввод игнорируется
		}
		switch msg.Type {
		case tea.KeyCtrlC:
			return m, tea.Quit
		case tea.KeyEnter:
			cmd, quit := m.dispatch()
			if cmd != "" {
				m.cmdCh <- cmd
			}
			m.input = ""
			if quit {
				return m, tea.Quit
			}
		case tea.KeyBackspace:
			// Delete whole runes so multi-byte input (Cyrillic, emoji)
			// survives editing.
			r := []rune(m.input)
			if len(r) > 0 {
				m.input = string(r[:len(r)-1])
			}
		case tea.KeyRunes:
			m.input += sanitize(string(msg.Runes), maxTextRunes)
		case tea.KeySpace:
			m.input += " "
		}
	}
	return m, nil
}

// dispatch interprets the input line for the current state. It returns the
// command for the network loop (possibly empty) and whether the program
// should quit.
func (m *model) dispatch() (string, bool) {
	switch m.state {
	case "setup_nick":
		nick := sanitize(strings.TrimSpace(m.input), maxNickRunes)
		if nick == "" {
			m.add(systemStyle.Render("* Никнейм не может быть пустым."))
			return "", false
		}
		m.nickname = nick
		m.state = "setup_room"
		m.add(systemStyle.Render("* Никнейм установлен: " + m.nickname))
		return "nick:" + m.nickname, false

	case "setup_room":
		line := strings.TrimSpace(m.input)
		switch {
		case line == "" || line == "/help":
			m.add(systemStyle.Render(helpText))
			return "", false
		case line == "/quit":
			return "", true
		case strings.HasPrefix(line, "/join "):
			kw := strings.TrimSpace(strings.TrimPrefix(line, "/join "))
			if kw == "" {
				m.add(systemStyle.Render("* Укажите кодовое слово: /join <слово>"))
				return "", false
			}
			m.keyword = kw
			m.state = "waiting"
			m.add(systemStyle.Render("* Поиск комнаты " + m.keyword + "..."))
			return "find:" + kw, false
		default:
			kw := line
			m.keyword = kw
			m.state = "waiting"
			m.add(systemStyle.Render("* Ожидание подключения по ключу " + m.keyword + "..."))
			return "register:" + kw, false
		}

	case "request":
		switch m.input {
		case "y", "Y":
			m.state = "waiting"
			m.add(systemStyle.Render("* Запрос принят. Установка соединения..."))
			return "accept", false
		case "n", "N":
			m.state = "setup_room"
			m.add(systemStyle.Render("* Запрос отклонен."))
			return "reject", false
		default:
			m.add(systemStyle.Render("* Ответьте y (да) или n (нет)."))
			return "", false
		}

	case "chat":
		line := m.input
		switch {
		case line == "/help":
			m.add(systemStyle.Render(helpText))
			return "", false
		case line == "/quit":
			return "", true
		case strings.HasPrefix(line, "/nick "):
			nick := sanitize(strings.TrimSpace(strings.TrimPrefix(line, "/nick ")), maxNickRunes)
			if nick == "" {
				m.add(systemStyle.Render("* Никнейм не может быть пустым."))
				return "", false
			}
			m.nickname = nick
			m.add(systemStyle.Render("* Никнейм изменён на " + nick))
			return "nick:" + nick, false
		case strings.HasPrefix(line, "/"):
			m.add(systemStyle.Render("* Неизвестная команда. /help — список команд."))
			return "", false
		case line != "":
			m.add(fmt.Sprintf("[%s]: %s", selfStyle.Render(m.nickname), line))
			return "msg:" + line, false
		}
	}
	return "", false
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
		s.WriteString("Кодовое слово (или /join <слово>, /help): ")
		s.WriteString(m.input)
		s.WriteString(cursorStyle.Render(cursorChar))
	case "waiting":
		s.WriteString(m.spinner.View() + " ")
		s.WriteString(systemStyle.Render("Ожидание... (Ctrl+C для выхода)"))
	case "waiting_handshake":
		s.WriteString(m.spinner.View() + " ")
		s.WriteString(systemStyle.Render("Согласование ключей..."))
	case "request":
		s.WriteString(errorStyle.Render("Разрешить подключение? (y/n): "))
		s.WriteString(m.input)
		s.WriteString(cursorStyle.Render(cursorChar))
	case "chat":
		prompt := "[" + m.nickname + "] > "
		// Keep the prompt + at least one rune of input on one line.
		maxRunes := m.width - utf8.RuneCountInString(prompt) - 2
		shown := m.input
		if maxRunes > 0 && utf8.RuneCountInString(shown) > maxRunes {
			r := []rune(shown)
			shown = string(r[len(r)-maxRunes:]) // видим хвост длинной строки
		}
		s.WriteString(selfStyle.Render(prompt))
		s.WriteString(shown)
		s.WriteString(cursorStyle.Render(cursorChar))
	case "dead":
		s.WriteString(errorStyle.Render("Соединение с сервером потеряно. Нажмите Ctrl+C для выхода."))
	}

	s.WriteString("\n\n")
	if m.state == "dead" {
		s.WriteString(systemStyle.Render("Нажмите Ctrl+C для выхода."))
	} else {
		s.WriteString(systemStyle.Render("Ctrl+C — выход. /help — справка."))
	}
	return s.String()
}
