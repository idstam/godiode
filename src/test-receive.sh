#!/bin/bash

DEST_DIR=~/temp/godiode_destination
TEMP_DIR=~/temp/godiode_temp

echo "Build godiode"
go build

echo "Start receiver"
echo "Dest: $DEST_DIR"
echo "Temp: $TEMP_DIR"

mkdir -p $DEST_DIR
mkdir -p $TEMP_DIR
rm -rf $DEST_DIR/*
./godiode  --secret 100000  --interface lo --verbose --tmpdir $TEMP_DIR -savemanifestpath $TEMP_DIR/../receiver.manifest.json receive $DEST_DIR
