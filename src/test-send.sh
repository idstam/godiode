#!/bin/bash

go build

cp godiode ~/temp
cd ~/temp

./godiode --secret 100000   --resendmanifest --packetsize 1300 --verbose --baddr 127.0.0.1:4010 --savemanifestpath /home/johan/temp/sender.manifest.json --resendcount 10 --bw 20  send  /home/johan/Sync/musik/

