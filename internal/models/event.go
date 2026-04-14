package models

import (
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ExecveEvent 表示execve系统调用事件
// 当进程执行新程序时触发，记录进程创建信息
type ExecveEvent struct {
	ID        uint64    `json:"id" gorm:"primaryKey"` // 数据库自增ID
	PID       uint32    `json:"pid"`                  // 进程ID
	PPID      uint32    `json:"ppid"`                 // 父进程ID
	Comm      string    `json:"comm"`                 // 进程名（可执行文件名）
	Argv0     string    `json:"argv0"`                // 执行的命令行参数
	CreatedAt time.Time `json:"created_at"`           // 事件创建时间
}

// NetworkEvent 表示网络数据包事件
// 记录系统网络活动，包括TCP/UDP/ICMP流量
type NetworkEvent struct {
	ID         uint64    `json:"id" gorm:"primaryKey"` // 数据库自增ID
	PID        uint32    `json:"pid"`                  // 关联的进程ID
	SrcIP      string    `json:"src_ip"`               // 源IP地址
	DstIP      string    `json:"dst_ip"`               // 目的IP地址
	SrcPort    uint16    `json:"src_port"`             // 源端口
	DstPort    uint16    `json:"dst_port"`             // 目的端口
	Protocol   uint8     `json:"protocol"`             // 协议号（6=TCP, 17=UDP, 1=ICMP）
	Direction  uint8     `json:"direction"`            // 方向：0=入站(ingress), 1=出站(egress)
	PacketSize uint32    `json:"packet_size"`          // 数据包大小（字节）
	Comm       string    `json:"comm"`                 // 进程名
	CreatedAt  time.Time `json:"created_at"`           // 事件创建时间
}

// ProcessNode 表示进程拓扑图中的节点
// 用于构建进程-文件-网络的关系图谱
type ProcessNode struct {
	PID       uint32    `json:"pid"`        // 进程ID
	PPID      uint32    `json:"ppid"`       // 父进程ID
	Comm      string    `json:"comm"`       // 进程名
	CreatedAt time.Time `json:"created_at"` // 进程启动时间
}

// NetworkConnection 表示网络连接关系
// 用于拓扑图展示进程的网络活动
type NetworkConnection struct {
	PID        uint32    `json:"pid"`         // 进程ID
	Comm       string    `json:"comm"`        // 进程名
	RemoteIP   string    `json:"remote_ip"`   // 远程IP
	RemotePort uint16    `json:"remote_port"` // 远程端口
	LocalPort  uint16    `json:"local_port"`  // 本地端口
	Protocol   string    `json:"protocol"`    // 协议类型
	Count      int       `json:"count"`       // 连接次数
	LastSeen   time.Time `json:"last_seen"`   // 最后活动时间
}

// DB 全局数据库连接实例
var DB *gorm.DB

// InitDB 初始化SQLite数据库
// 创建数据库文件并自动迁移表结构
func InitDB() (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open("sentinel.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// 自动迁移表结构
	// 如果表不存在则创建，如果字段有变化则更新
	err = db.AutoMigrate(&ExecveEvent{}, &NetworkEvent{})
	if err != nil {
		return nil, err
	}

	DB = db
	return db, nil
}

// CreateEvent 创建新的进程事件记录
func CreateEvent(event *ExecveEvent) error {
	return DB.Create(event).Error
}

// GetRecentEvents 获取最近的N条进程事件
// 按时间倒序排列，最新的在前面
func GetRecentEvents(limit int) ([]ExecveEvent, error) {
	var events []ExecveEvent
	result := DB.Order("created_at desc").Limit(limit).Find(&events)
	return events, result.Error
}

// CreateNetworkEvent 创建新的网络事件记录
func CreateNetworkEvent(event *NetworkEvent) error {
	return DB.Create(event).Error
}

// GetRecentNetworkEvents 获取最近的N条网络事件
func GetRecentNetworkEvents(limit int) ([]NetworkEvent, error) {
	var events []NetworkEvent
	result := DB.Order("created_at desc").Limit(limit).Find(&events)
	return events, result.Error
}

// GetProcessTopology 获取进程拓扑数据
// 返回所有进程及其父子关系，用于构建进程树
func GetProcessTopology() ([]ProcessNode, error) {
	var nodes []ProcessNode

	// 从execve事件中提取唯一的进程信息
	result := DB.Raw(`
		SELECT DISTINCT pid, ppid, comm, created_at 
		FROM execve_events 
		ORDER BY created_at DESC 
		LIMIT 1000
	`).Scan(&nodes)

	return nodes, result.Error
}

// GetNetworkTopology 获取网络连接拓扑
// 聚合网络事件，返回进程与远程地址的连接关系
func GetNetworkTopology() ([]NetworkConnection, error) {
	var connections []NetworkConnection

	result := DB.Raw(`
		SELECT 
			pid,
			comm,
			CASE 
				WHEN direction = 0 THEN src_ip 
				ELSE dst_ip 
			END as remote_ip,
			CASE 
				WHEN direction = 0 THEN src_port 
				ELSE dst_port 
			END as remote_port,
			CASE 
				WHEN direction = 0 THEN dst_port 
				ELSE src_port 
			END as local_port,
			CASE 
				WHEN protocol = 6 THEN 'TCP'
				WHEN protocol = 17 THEN 'UDP'
				ELSE 'OTHER'
			END as protocol,
			COUNT(*) as count,
			MAX(created_at) as last_seen
		FROM network_events
		GROUP BY pid, remote_ip, remote_port, protocol
		ORDER BY count DESC
		LIMIT 500
	`).Scan(&connections)

	return connections, result.Error
}
