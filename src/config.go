package main

import "io/fs"

type SenderConfig struct {
	Bw int `json:"bw"`
}

type ReceiverConfig struct {
	Delete           bool        `json:"delete"`
	FilePermission   fs.FileMode `json:"filePermission"`
	FolderPermission fs.FileMode `json:"folderPermission"`
	TmpDir           string      `json:"tmpDir"`
}

type Config struct {
	MaxPacketSize     int            `json:"maxPacketSize"`
	HMACSecret        string         `json:"hmacSecret"`
	MulticastAddr     string         `json:"multicastAddr"`
	BindAddr          string         `json:"bindAddr"`
	NIC               string         `json:"nic"`
	Verbose           bool           `json:"verbose"`
	Sender            SenderConfig   `json:"sender"`
	Receiver          ReceiverConfig `json:"receiver"`
	ResendCount       int            `json:"resendcount"`
	ResendManifest    bool           `json:"resendmanifest"`
	PacketLossPercent int            `json:"packetlosspercent"`
	KeepBrokenFiles   bool           `json:"keepbrokenfiles"`
	SaveManifestPath  string         `json:"savemanifestpath"`
	HashAlgo          string         `json:"hashAlgo"`
	IncludeFilters    arrayFlags     `json:"IncludeFilters"`
	ExcludeFilters    arrayFlags     `json:"ExcludeFilters"`
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var config = Config{
	MaxPacketSize:  1500 - 8 - 20,
	HMACSecret:     "",
	MulticastAddr:  "239.252.28.12:5432",
	BindAddr:       "",
	NIC:            "",
	ResendManifest: false,
	ResendCount:    1,
	Sender:         SenderConfig{Bw: 0},
	Receiver: ReceiverConfig{
		Delete:           false,
		FilePermission:   0600,
		FolderPermission: 0700,
		TmpDir:           "",
	},
	IncludeFilters: arrayFlags{},
	ExcludeFilters: arrayFlags{},
}
