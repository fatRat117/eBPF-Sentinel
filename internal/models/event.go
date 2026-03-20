package models

import (
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ExecveEvent 表示execve系统调用事件
type ExecveEvent struct {
	ID        uint64    `json:"id" gorm:"primaryKey"`
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	Comm      string    `json:"comm"`
	Argv0     string    `json:"argv0"`
	CreatedAt time.Time `json:"created_at"`
}

// NetworkEvent 表示网络数据包事件
type NetworkEvent struct {
	ID         uint64    `json:"id" gorm:"primaryKey"`
	PID        uint32    `json:"pid"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	SrcPort    uint16    `json:"src_port"`
	DstPort    uint16    `json:"dst_port"`
	Protocol   uint8     `json:"protocol"`
	Direction  uint8     `json:"direction"` // 0 = ingress, 1 = egress
	PacketSize uint32    `json:"packet_size"`
	Comm       string    `json:"comm"`
	CreatedAt  time.Time `json:"created_at"`
}

var DB *gorm.DB

// InitDB 初始化数据库
func InitDB() (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open("sentinel.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// 自动迁移
	err = db.AutoMigrate(&ExecveEvent{}, &NetworkEvent{})
	if err != nil {
		return nil, err
	}

	DB = db
	return db, nil
}

// CreateEvent 创建新的事件记录
func CreateEvent(event *ExecveEvent) error {
	return DB.Create(event).Error
}

// GetRecentEvents 获取最近的N条事件
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
