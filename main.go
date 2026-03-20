package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/ebpf-sentinel/internal/models"
	"github.com/ebpf-sentinel/internal/websocket"
	"github.com/gin-gonic/gin"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" execve ebpf/execve.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" network ebpf/network.c

type execveEvent struct {
	PID   uint32
	PPID  uint32
	Comm  [16]byte
	Argv0 [128]byte
}

type networkEvent struct {
	PID        uint32
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	Direction  uint8
	PacketSize uint32
	Comm       [16]byte
}

func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		(ip>>8)&0xFF,
		ip&0xFF,
	)
}

func protocolToString(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("%d", p)
	}
}

// getNetworkInterfaces 获取所有活动的网络接口
func getNetworkInterfaces() []*net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var result []*net.Interface
	for i := range ifaces {
		iface := &ifaces[i]
		// 跳过回环接口和未启用的接口
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		result = append(result, iface)
	}
	return result
}

// attachNetworkProgram 挂载网络eBPF程序到指定接口
func attachNetworkProgram(objs *networkObjects, ifaceIdx int, isIngress bool) (link.Link, error) {
	var prog *ebpf.Program
	var attachType ebpf.AttachType

	if isIngress {
		prog = objs.TcIngress
		attachType = ebpf.AttachTCXIngress
	} else {
		prog = objs.TcEgress
		attachType = ebpf.AttachTCXEgress
	}

	// 使用TCX（TC eXpress）API挂载
	tcxOpts := link.TCXOptions{
		Interface: ifaceIdx,
		Program:   prog,
		Attach:    attachType,
	}

	return link.AttachTCX(tcxOpts)
}

func main() {
	// 初始化数据库
	_, err := models.InitDB()
	if err != nil {
		log.Fatalf("failed to init database: %v", err)
	}
	log.Println("Database initialized")

	// 创建WebSocket Hub
	hub := websocket.NewHub()
	go hub.Run()

	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock limit: %v", err)
	}

	// ========== 加载 execve eBPF 程序 ==========
	execveObjs := execveObjects{}
	if err := loadExecveObjects(&execveObjs, nil); err != nil {
		log.Fatalf("failed to load execve objects: %v", err)
	}
	defer execveObjs.Close()

	execveTp, err := link.Tracepoint("syscalls", "sys_enter_execve", execveObjs.TracepointExecve, nil)
	if err != nil {
		log.Fatalf("failed to attach execve tracepoint: %v", err)
	}
	defer execveTp.Close()

	execveRd, err := ringbuf.NewReader(execveObjs.Events)
	if err != nil {
		log.Fatalf("failed to open execve ring buffer: %v", err)
	}
	defer execveRd.Close()

	// 读取execve事件
	go func() {
		for {
			record, err := execveRd.Read()
			if err != nil {
				log.Printf("[execve] failed to read from ring buffer: %v", err)
				return
			}

			var event execveEvent
			if len(record.RawSample) < 152 {
				continue
			}

			copy((*[152]byte)(unsafe.Pointer(&event))[:], record.RawSample)

			comm := string(bytes.Trim(event.Comm[:], "\x00"))
			argv0 := string(bytes.Trim(event.Argv0[:], "\x00"))

			// 保存到数据库
			dbEvent := &models.ExecveEvent{
				PID:   event.PID,
				PPID:  event.PPID,
				Comm:  comm,
				Argv0: argv0,
			}
			if err := models.CreateEvent(dbEvent); err != nil {
				log.Printf("[execve] failed to save event: %v", err)
			}

			// 通过WebSocket实时推送
			hub.Broadcast(map[string]interface{}{
				"type": "execve",
				"data": map[string]interface{}{
					"pid":   event.PID,
					"ppid":  event.PPID,
					"comm":  comm,
					"argv0": argv0,
				},
			})

			log.Printf("[EXECVE] PID=%d PPID=%d Comm=%s Argv0=%s",
				event.PID, event.PPID, comm, argv0)
		}
	}()

	// ========== 加载 network eBPF 程序 ==========
	networkObjs := networkObjects{}
	if err := loadNetworkObjects(&networkObjs, nil); err != nil {
		log.Printf("[network] failed to load network objects: %v", err)
		log.Println("[network] Network monitoring disabled")
	} else {
		defer networkObjs.Close()

		// 获取所有活动的网络接口
		interfaces := getNetworkInterfaces()
		if len(interfaces) == 0 {
			log.Println("[network] No active network interfaces found")
			log.Println("[network] Network monitoring disabled")
		} else {
			var interfaceNames []string
			for _, iface := range interfaces {
				interfaceNames = append(interfaceNames, iface.Name)
			}
			log.Printf("[network] Found interfaces: %s", strings.Join(interfaceNames, ", "))

			var attachedInterfaces []string

			// 尝试挂载到每个接口
			for _, iface := range interfaces {
				// 挂载ingress程序
				ingressLink, err := attachNetworkProgram(&networkObjs, iface.Index, true)
				if err != nil {
					log.Printf("[network] failed to attach ingress to %s: %v", iface.Name, err)
					continue
				}
				defer ingressLink.Close()

				// 挂载egress程序
				egressLink, err := attachNetworkProgram(&networkObjs, iface.Index, false)
				if err != nil {
					log.Printf("[network] failed to attach egress to %s: %v", iface.Name, err)
					ingressLink.Close()
					continue
				}
				defer egressLink.Close()

				attachedInterfaces = append(attachedInterfaces, iface.Name)
				log.Printf("[network] Successfully attached to %s", iface.Name)
			}

			if len(attachedInterfaces) == 0 {
				log.Println("[network] Failed to attach to any interface")
				log.Println("[network] Network monitoring disabled")
			} else {
				log.Printf("[network] Monitoring interfaces: %s", strings.Join(attachedInterfaces, ", "))

				networkRd, err := ringbuf.NewReader(networkObjs.NetEvents)
				if err != nil {
					log.Printf("[network] failed to open network ring buffer: %v", err)
				} else {
					defer networkRd.Close()

					// 读取network事件
					go func() {
						for {
							record, err := networkRd.Read()
							if err != nil {
								log.Printf("[network] failed to read from ring buffer: %v", err)
								return
							}

							var event networkEvent
							if len(record.RawSample) < 28 {
								continue
							}

							// 解析网络事件结构
							event.PID = binary.LittleEndian.Uint32(record.RawSample[0:4])
							event.SrcIP = binary.LittleEndian.Uint32(record.RawSample[4:8])
							event.DstIP = binary.LittleEndian.Uint32(record.RawSample[8:12])
							event.SrcPort = binary.LittleEndian.Uint16(record.RawSample[12:14])
							event.DstPort = binary.LittleEndian.Uint16(record.RawSample[14:16])
							event.Protocol = record.RawSample[16]
							event.Direction = record.RawSample[17]
							event.PacketSize = binary.LittleEndian.Uint32(record.RawSample[18:22])
							copy(event.Comm[:], record.RawSample[22:38])

							comm := string(bytes.Trim(event.Comm[:], "\x00"))
							srcIP := ipToString(event.SrcIP)
							dstIP := ipToString(event.DstIP)
							proto := protocolToString(event.Protocol)
							direction := "ingress"
							if event.Direction == 1 {
								direction = "egress"
							}

							// 保存到数据库
							dbEvent := &models.NetworkEvent{
								PID:        event.PID,
								SrcIP:      srcIP,
								DstIP:      dstIP,
								SrcPort:    event.SrcPort,
								DstPort:    event.DstPort,
								Protocol:   event.Protocol,
								Direction:  event.Direction,
								PacketSize: event.PacketSize,
								Comm:       comm,
							}
							if err := models.CreateNetworkEvent(dbEvent); err != nil {
								log.Printf("[network] failed to save event: %v", err)
							}

							// 通过WebSocket实时推送
							hub.Broadcast(map[string]interface{}{
								"type": "network",
								"data": map[string]interface{}{
									"pid":         event.PID,
									"src_ip":      srcIP,
									"dst_ip":      dstIP,
									"src_port":    event.SrcPort,
									"dst_port":    event.DstPort,
									"protocol":    proto,
									"direction":   direction,
									"packet_size": event.PacketSize,
									"comm":        comm,
								},
							})

							log.Printf("[NETWORK] %s %s PID=%d %s:%d -> %s:%d (%s) %d bytes",
								direction, proto, event.PID, srcIP, event.SrcPort, dstIP, event.DstPort, comm, event.PacketSize)
						}
					}()
				}
			}
		}
	}

	log.Println("eBPF Sentinel started! Monitoring execve syscalls and network traffic...")

	// 设置Gin路由
	r := gin.Default()

	// API路由
	r.GET("/api/events", func(c *gin.Context) {
		events, err := models.GetRecentEvents(100)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, events)
	})

	r.GET("/api/network-events", func(c *gin.Context) {
		events, err := models.GetRecentNetworkEvents(100)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, events)
	})

	// WebSocket路由
	r.GET("/ws", func(c *gin.Context) {
		hub.ServeWs(c.Writer, c.Request)
	})

	// 静态文件服务
	r.Static("/assets", "./web/dist/assets")
	r.StaticFile("/", "./web/dist/index.html")
	r.NoRoute(func(c *gin.Context) {
		c.File("./web/dist/index.html")
	})

	log.Println("API server started on :8080")
	log.Println("WebSocket endpoint: ws://localhost:8080/ws")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
