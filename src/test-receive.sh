#!/bin/bash

go build

rm -rf /home/johan/temp/godiode_destination/*
./godiode  --secret 100000  --interface lo --verbose --tmpdir /home/johan/temp/godiode_temp/ -savemanifestpath /home/johan/temp/receiver.manifest.json receive /home/johan/temp/godiode_destination/
