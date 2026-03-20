package plugin

import (
	"bytes"
	"log"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ExecveEvent 对应eBPF中的事件结构
type ExecveEvent struct {
	PID   uint32
	PPID  uint32
	Comm  [16]byte
	Argv0 [128]byte
}

// execveObjects 由bpf2go生成的对象结构
type execveObjects struct {
	TracepointExecve *ebpf.Program `ebpf:"tracepoint_execve"`
	Events           *ebpf.Map     `ebpf:"events"`
}

func (o *execveObjects) Close() error {
	if o.TracepointExecve != nil {
		o.TracepointExecve.Close()
	}
	if o.Events != nil {
		o.Events.Close()
	}
	return nil
}

// ExecvePlugin execve监控插件
type ExecvePlugin struct {
	BasePlugin
	objs      *execveObjects
	reader    *ringbuf.Reader
	eventChan chan<- *Event
}

// NewExecvePlugin 创建execve插件
func NewExecvePlugin() *ExecvePlugin {
	return &ExecvePlugin{
		BasePlugin: BasePlugin{
			Name_:        "execve",
			Description_: "Monitor execve system calls",
		},
	}
}

// Load 加载eBPF对象
func (p *ExecvePlugin) Load() error {
	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// 这里需要实际加载eBPF对象
	// 由于bpf2go生成的代码在main包，我们需要重新组织代码结构
	// 暂时使用占位符
	log.Printf("[%s] Loading eBPF objects...", p.Name_)
	return nil
}

// Attach 挂载eBPF程序
func (p *ExecvePlugin) Attach() error {
	if p.objs == nil || p.objs.TracepointExecve == nil {
		return nil // 占位符实现
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", p.objs.TracepointExecve, nil)
	if err != nil {
		return err
	}
	p.Links = append(p.Links, tp)

	// 打开ring buffer
	reader, err := ringbuf.NewReader(p.objs.Events)
	if err != nil {
		return err
	}
	p.reader = reader

	return nil
}

// Close 清理资源
func (p *ExecvePlugin) Close() error {
	if p.reader != nil {
		p.reader.Close()
	}
	if p.objs != nil {
		p.objs.Close()
	}
	return nil
}

// Start 开始读取事件
func (p *ExecvePlugin) Start(eventChan chan<- *Event) error {
	p.eventChan = eventChan

	if p.reader == nil {
		return nil // 占位符实现
	}

	for {
		record, err := p.reader.Read()
		if err != nil {
			log.Printf("[%s] failed to read from ring buffer: %v", p.Name_, err)
			return err
		}

		var e ExecveEvent
		if len(record.RawSample) < 152 {
			continue
		}

		copy((*[152]byte)(unsafe.Pointer(&e))[:], record.RawSample)

		comm := string(bytes.Trim(e.Comm[:], "\x00"))
		argv0 := string(bytes.Trim(e.Argv0[:], "\x00"))

		event := &Event{
			Type:      "execve",
			Timestamp: time.Now().Unix(),
			Data: map[string]interface{}{
				"pid":   e.PID,
				"ppid":  e.PPID,
				"comm":  comm,
				"argv0": argv0,
			},
		}

		select {
		case eventChan <- event:
		default:
			log.Printf("[%s] event channel full, dropping event", p.Name_)
		}
	}
}
