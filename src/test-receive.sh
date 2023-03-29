#!/bin/bash

go build

./godiode --interface lo --verbose --tmpdir /home/johan/temp/godiode_temp/ -savemanifestpath /home/johan/temp/receiver.manifest.json -hashalgo none receive /home/johan/temp/godiode_destination/
