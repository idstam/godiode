package main

import (
	"flag"
	"os"
	"testing"
)

func TestReceive(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	cases := []struct {
		Name           string
		Args           []string
		ExpectedExit   int
		ExpectedOutput string
	}{

		{"receive", []string{"-secret", "00000000", "-hashalgo", "none", "--interface", "lo", "--verbose", "--tmpdir", "/home/johan/temp/godiode_temp/", "-savemanifestpath", "/home/johan/temp/receiver.manifest.json", "receive", "/home/johan/temp/godiode_destination/"}, 0, "xx"},
	}
	for _, tc := range cases {
		// this call is required because otherwise flags panics, if args are set between flag.Parse calls
		flag.CommandLine = flag.NewFlagSet(tc.Name, flag.ExitOnError)
		// we need a value to set Args[0] to, cause flag begins parsing at Args[1]
		os.Args = append([]string{tc.Name}, tc.Args...)
		main()
	}
}
