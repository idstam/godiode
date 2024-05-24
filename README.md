
# File transfer over UDP
This project is a fork from https://github.com/klockcykel/godiode

I have made a lot of changes to make it work for large data sets in a production environment.

If your company want to fund the developer please [create an invoice](https://invoice.jsisoft.se) for you finance department.

## Software
With recommended OS optimizations it should reach 750+ Mbit/s file transfers.

These changes make this a little less PoC and more robust for production use. 

 -  added resending of the manifest to enable starting a listener in the middle of a sending session.
 -  keep received data and continue appending on resend to handle package loss within a file
 -  resend everything with the same manifest to handle package loss
 -  randomly drop packages for testing purposes
 -  don't overwrite already received files if they are the same
 -  keep running the receiver until all files are received
 -  optional hash algorithms
 -  glob filters for files
 

### Build instructions
With local golang available
```
# apt install golang
cd src && go build -o ../bin/godiode . ; cd .. 
```

With golang in docker
```
# apt install golang
docker-compose run --rm build
```

The built binary will end up in _./bin/godiode_

### Running
### Usage
```
Usage: godiode <options> send|receive <dir>
  -baddr string
    	bind address
  -bw int
    	throttle bw to X Mbit/s (sender only)
  -conf string
    	JSON config file (default "/etc/godiode.json")
  -delete
    	delete files (receiver only)
  -interface string
    	interface to bind to
  -maddr string
    	multicast address (default "239.252.28.12:5432")
  -packetsize int
    	maximum UDP payload size (default 1472)
  -secret string
    	HMAC secret to protect file headers and footers
  -tmpdir string
    	tmp dir to use (receiver only)
  -verbose
    	verbose output
  -resendcount
        how many times to re-transmit from the sender (sender only)
  -resendmanifest
        resend the manifest between every file (sender only)
  -fakepacketlosspercent
        randomly drop packages (sender only)
  -keepbrokenfiles
        rename broken received temp files instead of deleting them (receiver only)
  -savemanifestpath string
        save the transfer manifest to disk
  -hashalgo
        hashing algorithm for validating files. [sha256, sha1, md5, none] default is sha256
  -include
        glob filter for files to include, can be used multiple times (sender only)
  -exclude
        glob filter for files to exclude, can be used multiple times (sender only)
```
#### Receiver
Replace eth0 with nic connected to diode, received data will end up in ./in
```
mkdir -p in/ && ./bin/godiode --verbose --interface eth0 receive in/
```
Or using docker...
```
docker-compose run --rm godiode --verbose --interface eth0 receive /in
```

#### Sender
Place folder structure to transfer under ./out and replace IP with whatever you assigned the nic connected to the diode.
```
mkdir -p out && ./bin/godiode --verbose --baddr 10.72.0.1:1234 send out/
```
Or using docker...
```
docker-compose run --rm godiode --verbose --baddr 10.72.0.1:1234 send /out
```

### Optimize for speed
#### Use jumbo frames
For optimal performance it's recommended to use jumbo frames. Enable on your interfaces (both sender and receiver):
```
# replace eth0 with nic connected to diode
sudo ip link set mtu 9000 eth0
```
Instruct sender/receiver to use larger packets with _packetsize_-flag to godiode
```
godiode --packetsize 8972 send /out
```

#### Increase send/receive buffers
Receiver will try and allocate a buffer of 300xPacketsize, so with jumbo frames the net.core.rm_max should be set to at least 2700000 in either /etc/sysctl.conf or manually with
```
sudo sysctl net.core.rmem_max=2700000
```




