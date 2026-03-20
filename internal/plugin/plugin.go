package plugin

import (
	"github.com/cilium/ebpf/link"
)

// Event 通用事件结构
type Event struct {
	Type      string                 `json:"type"`
	Timestamp int64                  `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// Plugin 接口定义
type Plugin interface {
	// Name 返回插件名称
	Name() string

	// Description 返回插件描述
	Description() string

	// Load 加载eBPF对象
	Load() error

	// Attach 挂载eBPF程序到内核
	Attach() error

	// Detach 卸载eBPF程序
	Detach() error

	// Close 清理资源
	Close() error

	// Start 开始读取事件（阻塞调用，应在goroutine中运行）
	Start(eventChan chan<- *Event) error
}

// BasePlugin 基础插件结构
type BasePlugin struct {
	Name_        string
	Description_ string
	Objs         interface{}
	Links        []link.Link
}

func (bp *BasePlugin) Name() string {
	return bp.Name_
}

func (bp *BasePlugin) Description() string {
	return bp.Description_
}

func (bp *BasePlugin) Detach() error {
	for _, l := range bp.Links {
		if l != nil {
			l.Close()
		}
	}
	bp.Links = nil
	return nil
}

// Manager 插件管理器
type Manager struct {
	plugins map[string]Plugin
}

// NewManager 创建插件管理器
func NewManager() *Manager {
	return &Manager{
		plugins: make(map[string]Plugin),
	}
}

// Register 注册插件
func (m *Manager) Register(p Plugin) {
	m.plugins[p.Name()] = p
}

// Get 获取插件
func (m *Manager) Get(name string) (Plugin, bool) {
	p, ok := m.plugins[name]
	return p, ok
}

// List 列出所有插件
func (m *Manager) List() []Plugin {
	list := make([]Plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		list = append(list, p)
	}
	return list
}

// LoadAll 加载所有插件
func (m *Manager) LoadAll() error {
	for _, p := range m.plugins {
		if err := p.Load(); err != nil {
			return err
		}
	}
	return nil
}

// AttachAll 挂载所有插件
func (m *Manager) AttachAll() error {
	for _, p := range m.plugins {
		if err := p.Attach(); err != nil {
			return err
		}
	}
	return nil
}

// DetachAll 卸载所有插件
func (m *Manager) DetachAll() error {
	for _, p := range m.plugins {
		if err := p.Detach(); err != nil {
			return err
		}
	}
	return nil
}

// CloseAll 关闭所有插件
func (m *Manager) CloseAll() error {
	for _, p := range m.plugins {
		if err := p.Close(); err != nil {
			return err
		}
	}
	return nil
}
