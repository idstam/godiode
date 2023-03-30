package main

import (
	"flag"
	"os"
	"testing"
)

func TestSend(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	cases := []struct {
		Name           string
		Args           []string
		ExpectedExit   int
		ExpectedOutput string
	}{

		{"send", []string{"-secret", "", "-hashalgo", "none", "--resendmanifest", "--verbose", "--baddr", "127.0.0.1:4010", "-savemanifestpath", "/home/johan/temp/sender.manifest.json", "-resendcount", "10", "-bw", "200", "send", "/home/johan/Sync/musik/A/Aqua"}, 0, "xx"},
	}
	for _, tc := range cases {
		// this call is required because otherwise flags panics, if args are set between flag.Parse calls
		flag.CommandLine = flag.NewFlagSet(tc.Name, flag.ExitOnError)
		// we need a value to set Args[0] to, cause flag begins parsing at Args[1]
		os.Args = append([]string{tc.Name}, tc.Args...)
		main()
	}
}
