#!/bin/bash

TEMP_DIR=~/temp
SOURCE_DIR=~/Sync/musik/

read -p "Did you start the test receiver? Press any key to continue... " -n1 -s

cp godiode $TEMP_DIR
cd $TEMP_DIR

echo "Starting sender"
echo "Source: $SOURCE_DIR"

./godiode --secret 100000   --resendmanifest --packetsize 1300 --verbose --baddr 127.0.0.1:4010 --savemanifestpath $TEMP_DIR/sender.manifest.json --resendcount 10 --bw 20  send $SOURCE_DIR

