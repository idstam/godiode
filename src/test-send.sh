#!/bin/bash

go build

cp godiode ~/temp
cd ~/temp

./godiode --resendmanifest --verbose --baddr 127.0.0.1:4010 -savemanifestpath /home/johan/temp/sender.manifest.json -resendcount 10 -bw 200 -hashalgo none send  /home/johan/Sync/musik/A/

