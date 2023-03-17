#!/bin/bash

go build

cp godiode ~/temp

./godiode --interface lo --verbose --tmpdir /home/johan/temp/godiode_temp/ -savemanifestpath /home/johan/temp/receiver.manifest.json receive /home/johan/temp/godiode_destination/
