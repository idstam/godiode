package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"time"
)

const DEFAULT_CONF_PATH = "/etc/godiode.json"

func init() {
	rand.Seed(time.Now().UnixNano())
}

func printUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: godiode <options> send|receive <dir>\n")
	flag.PrintDefaults()
}

func usageError(msg string) {
	fmt.Fprint(os.Stderr, "Error: ")
	fmt.Fprint(os.Stderr, msg)
	fmt.Fprint(os.Stderr, "\n\n")
	printUsage()
	os.Exit(1)
}

func checkCommonArgs() {
	if config.HMACSecret == "" {
		fmt.Fprintf(os.Stderr, "Warning: HMAC secret not set\n")
	}
	if config.HashAlgo == "" {
		config.HashAlgo = "sha256"
	}
	//TODO: check more args...
}

func loadConfigFile(configFilePath string) (*Config, error) {
	jsonFile, err := os.Open(configFilePath)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()

	data, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}
	fileConfig := config
	fileConfig.Sender = config.Sender
	fileConfig.Receiver = config.Receiver
	err = json.Unmarshal(data, &fileConfig)
	return &fileConfig, err
}

func main() {

	confFile := DEFAULT_CONF_PATH
	flag.StringVar(&confFile, "conf", confFile, "JSON config file")
	flag.IntVar(&config.MaxPacketSize, "packetsize", config.MaxPacketSize, "maximum UDP payload size")
	flag.StringVar(&config.HMACSecret, "secret", config.HMACSecret, "HMAC secret")
	flag.IntVar(&config.Sender.Bw, "bw", config.Sender.Bw, "throttle bw to X Mbit/s (sender only)")
	flag.StringVar(&config.MulticastAddr, "maddr", config.MulticastAddr, "multicast address")
	flag.StringVar(&config.BindAddr, "baddr", config.BindAddr, "bind address")
	flag.StringVar(&config.NIC, "interface", config.NIC, "interface to bind to")
	flag.BoolVar(&config.Receiver.Delete, "delete", config.Receiver.Delete, "delete files (receiver only)")
	flag.BoolVar(&config.Verbose, "verbose", config.Verbose, "verbose output")
	flag.StringVar(&config.Receiver.TmpDir, "tmpdir", config.Receiver.TmpDir, "tmp dir to use (receiver only)")
	flag.IntVar(&config.ResendCount, "resendcount", config.ResendCount, "how many times to re-transmit from the sender")
	flag.BoolVar(&config.ResendManifest, "resendmanifest", config.ResendManifest, "resend the manifest once between every 10MB of file data")
	flag.IntVar(&config.PacketLossPercent, "fakepacketlosspercent", config.PacketLossPercent, "randomly drop packages")
	flag.BoolVar(&config.KeepBrokenFiles, "keepbrokenfiles", config.KeepBrokenFiles, "rename broken temp files instead of deleting them")
	flag.StringVar(&config.SaveManifestPath, "savemanifestpath", config.SaveManifestPath, "save the transfer manifest to disk, works both both ends")
	flag.StringVar(&config.HashAlgo, "hashalgo", config.HashAlgo, "hashing algorithm for validating files. [sha256, sha1, md5, none] default is sha256")
	flag.Var(&config.IncludeFilters, "include", "glob filter for files to include, can be used multiple times")
	flag.Var(&config.ExcludeFilters, "exclude", "glob filter for files to exclude, can be used multiple times")
	flag.Parse()

	// load defaults from file
	fileConfig, err := loadConfigFile(confFile)
	if err != nil && confFile != DEFAULT_CONF_PATH {
		_, _ = fmt.Fprintf(os.Stderr, "Error reading config: "+err.Error()+"\n")
		os.Exit(1)
	}

	if fileConfig != nil {
		config = *fileConfig
		// override file conf with args
		flag.Parse()
		config.IncludeFilters = arrayFlags{}
		config.ExcludeFilters = arrayFlags{}
	}

	if len(os.Args) < 3 {
		usageError("Missing required arguments")
	}
	sender := os.Args[len(os.Args)-2] == "send"
	receiver := os.Args[len(os.Args)-2] == "receive"
	if !sender && !receiver {
		usageError("Missing required send|receive command")
	}

	dir := os.Args[len(os.Args)-1]
	finfo, err := os.Stat(dir)
	if err != nil {
		usageError(err.Error())
	}

	if receiver {
		if !finfo.IsDir() {
			usageError("Invalid receive dir")
		}
		checkCommonArgs()
		err = receive(&config, dir)
	}

	if sender {
		checkCommonArgs()
		err = send(&config, dir)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
}
