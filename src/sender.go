package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"math/rand"
	"net"
	"os"
	"path"
	"strings"
	"time"
)

const HEADER_OVERHEAD = 6 + 6 + 2 + 4 + 20 + 8

var THROTTLE = struct {
	enabled    bool
	tokens     int64
	capacity   int64
	last       time.Time
	nsPerToken float64
}{}

/**
 * Protocol format
 *
 * | type | payload... |
 * type - uint8
 *   0x01 - manifest
 *   0x02 - file transfer start
 *   0x03 - file transfer Complete
 *   0x80-0xFF - file transfer data
 *
 * manifest
 * | type | id | part | [Size] | payload
 * type - uint8 - 0x01
 * id - uint32 - manifest session id
 * part - uint16 - manifest session part index
 * Size - uint32 - total manifest Size, only sent in part 0
 * payload | manifest chunk
 *
 */

func sendManifest(conf *Config, c *net.UDPConn, manifest *Manifest, manifestId uint32, resendCount int) error {

	if conf.MaxPacketSize < 14 {
		return errors.New("too small packet max Size for sending manifest")
	}
	manifestData, err := manifest.serializeManifest(conf)
	if err != nil {
		return err
	}

	sentCount := 0
	for rs := 0; rs < resendCount; rs++ {
		sentCount++
		if conf.Verbose {
			fmt.Printf("sending manifest round %d of %d \n", sentCount, resendCount)
		}
		buff := make([]byte, conf.MaxPacketSize)
		buff[0] = 0x01
		binary.BigEndian.PutUint32(buff[1:], manifestId)

		offset := 0
		var i uint32

		for i = 0; offset < len(manifestData); i++ {
			binary.BigEndian.PutUint32(buff[5:], i)
			l := 9
			copied := 0
			if i == 0 {
				binary.BigEndian.PutUint32(buff[l:], uint32(len(manifestData)))
				l += 4
				copied = copy(buff[l:], manifestData[offset:])
				l += copied
				offset += copied
			} else {
				copied = copy(buff[l:], manifestData[offset:])
				l += copied
				offset += copied
			}

			if conf.PacketLossPercent == 0 || rand.Intn(100) > conf.PacketLossPercent {
				_, _ = c.Write(buff[:l])
			}

			throttle(copied)
		}

	}
	return nil
}

/*
 * file transfer start packet
 *
 * type - uint8 - 0x02
 * filetype - uint8 - 0x00 (regular file)
 * manifestSessionId - uint32 - manifest session id
 * fileIndex - uint32 - file index in the manifest
 * Size - uint64 - Size of file in bytes
 * mtime - int64 - unix millis
 * sign - byte[64] - hmac512 of this packet
 *
 *
 * file data packet
 *
 * type - 0x80
 * manifestSessionId - uint32 - manifest session id
 * fileIndex - uint32 - file index in the manifest
 * packageIndex - uint32
 * data - up to max payload Size
 *
 *
 *
 * file transfer Complete packet
 *
 * type - uint8 - 0x03
 * manifestSessionId - uint32 - manifest session id
 * fileIndex - uint32 - file index in the manifest
 * hash - byte[32] - sha256 of file content
 * sign - byte[64] - hmac512 of this packet
 */
func sendFile(conf *Config, c *net.UDPConn, manifestId uint32, fIndex uint32, f string) error {
	finfo, err := os.Stat(f)
	if err != nil {
		return err
	}

	file, err := os.Open(f)
	if err != nil {
		return err
	}
	defer file.Close()

	if conf.Verbose {
		fmt.Println("Sending file " + f)
	}

	buff := make([]byte, conf.MaxPacketSize)

	buff[0] = 0x02
	buff[1] = 0x00
	binary.BigEndian.PutUint32(buff[2:], manifestId)
	binary.BigEndian.PutUint32(buff[6:], fIndex)
	binary.BigEndian.PutUint64(buff[10:], uint64(finfo.Size()))
	binary.BigEndian.PutUint64(buff[18:], uint64(finfo.ModTime().Unix()))
	if conf.HMACSecret != "" {
		h512 := sha512.New()
		_, _ = io.WriteString(h512, conf.HMACSecret)
		mac := hmac.New(sha512.New, h512.Sum(nil))
		mac.Write(buff[:26])
		copy(buff[26:], mac.Sum(nil))
		_, _ = c.Write(buff[:26+64])
	} else {
		_, _ = c.Write(buff[:26])
	}
	time.Sleep(50 * time.Millisecond)

	buff[0] = 0x80
	var packetIndex uint32

	//	pos := 0
	binary.BigEndian.PutUint32(buff[1:], manifestId)
	binary.BigEndian.PutUint32(buff[5:], fIndex)
	for {
		binary.BigEndian.PutUint32(buff[9:], packetIndex)
		read, err := file.Read(buff[13:])
		//		fmt.Println("read=%d", read, err)
		if read == 0 {
			break
		}
		if err != nil {
			return errors.New("Failed to read file: " + err.Error())
		}

		throttle(read)
		if conf.PacketLossPercent == 0 || rand.Intn(100) > conf.PacketLossPercent {
			_, _ = c.Write(buff[:(read + 13)])
		}
		packetIndex++
	}

	_ = file.Close()
	hs, err := getSendFileHash(f, conf.HashAlgo)
	if err != nil {
		return err
	}

	buff[0] = 0x03
	binary.BigEndian.PutUint32(buff[1:], manifestId)
	binary.BigEndian.PutUint32(buff[5:], fIndex)
	copy(buff[9:], hs)
	if conf.HMACSecret != "" {
		h512 := sha512.New()
		_, _ = io.WriteString(h512, conf.HMACSecret)
		mac := hmac.New(sha512.New, h512.Sum(nil))
		mac.Write(buff[:9+32])
		copy(buff[9+32:], mac.Sum(nil))
		_, _ = c.Write(buff[:9+32+64])
	} else {
		_, _ = c.Write(buff[:9+32])

	}
	if conf.Verbose {
		fmt.Println("Sent file " + f + ", checksum=" + hex.EncodeToString(hs))
	}

	time.Sleep(100 * time.Millisecond)

	return nil
}

func throttle(read int) {
	if THROTTLE.enabled {
		plen := read + 1 + HEADER_OVERHEAD
		for {
			if THROTTLE.tokens >= int64(plen) {
				THROTTLE.tokens -= int64(plen)
				break
			}
			now := time.Now()
			ns := time.Duration.Nanoseconds(now.Sub(THROTTLE.last))
			//log.Println(ns, ns/THROTTLE.nsPerToken, THROTTLE.tokens)
			newValue := THROTTLE.tokens + int64(math.Round(float64(ns)/THROTTLE.nsPerToken))
			if newValue >= int64(plen) {
				THROTTLE.tokens = newValue
				if THROTTLE.tokens > THROTTLE.capacity {
					THROTTLE.tokens = THROTTLE.capacity
				}
				THROTTLE.last = now
			} else {
				sleepTime := math.Ceil(float64(int64(plen)-newValue) * THROTTLE.nsPerToken)
				//log.Println(sleepTime, THROTTLE.tokens)
				time.Sleep(time.Duration(sleepTime))
			}
		}
	}
}

func send(conf *Config, dir string) error {

	dir = path.Clean(dir)

	manifest, err := generateManifest(dir, conf.SaveManifestPath, conf.IncludeFilters, conf.ExcludeFilters)
	if err != nil {
		return err
	}

	if len(manifest.Files) == 0 && len(manifest.Dirs) == 0 {
		return errors.New("no files to send")
	}

	maddr, err := net.ResolveUDPAddr("udp", conf.MulticastAddr)
	if err != nil {
		return err
	}
	var baddr *net.UDPAddr = nil
	if conf.BindAddr != "" {
		baddr, err = net.ResolveUDPAddr("udp", conf.BindAddr)
		if err != nil {
			return err
		}
	}
	c, err := net.DialUDP("udp", baddr, maddr)
	if err != nil {
		return err
	}
	defer c.Close()
	err = c.SetWriteBuffer(10 * conf.MaxPacketSize)
	if err != nil {
		return err
	}

	if conf.Sender.Bw > 0 {
		THROTTLE.enabled = true
		bytesPerSecond := int64(1024 * 1024 * conf.Sender.Bw / 8)
		THROTTLE.nsPerToken = float64(1024*1024*1024) / float64(bytesPerSecond)
		THROTTLE.capacity = 13 * int64(conf.MaxPacketSize+HEADER_OVERHEAD)
		THROTTLE.tokens = THROTTLE.capacity
		THROTTLE.last = time.Now()
	}
	manifestId := rand.Uint32()
	err = sendManifest(conf, c, manifest, manifestId, conf.ResendCount)
	if err != nil {
		return err
	}

	// wait some to let the receiver create Dirs etc
	time.Sleep(2000 * time.Millisecond)

	//	log.Println(THROTTLE.nsPerToken, THROTTLE.capacity, THROTTLE.tokens, THROTTLE.last)

	for rs := 0; rs < conf.ResendCount; rs++ {

		finfo, err := os.Stat(dir)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error sending : "+err.Error()+"\n")
			return err
		}

		if !finfo.IsDir() {
			err = sendFile(conf, c, manifestId, 0, dir)
			return err
		} else {

			dir = path.Clean(dir) + "/"

			sentSize := int64(0)
			for i := 0; i < len(manifest.Files); i++ {

				err = sendFile(conf, c, manifestId, uint32(i), dir+manifest.Files[i].Path)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "Error sending file: "+manifest.Files[i].Path+" "+err.Error()+"\n")
					continue
				}
				sentSize += manifest.Files[i].Size
				if conf.ResendManifest && sentSize > (10*1028*1028) { //We do not want to saturate the channel with manifest data when there are lots of small Files to send.
					sentSize = 0
					err = sendManifest(conf, c, manifest, manifestId, 1)
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "Error sending manifest: "+err.Error()+"\n")
						return err
					}

				}
			}
		}

		if conf.Verbose {
			fmt.Printf("All Files sent. Transmission %d of %d \n", rs+1, conf.ResendCount)
		}
	}
	return nil
}
func getSendFileHash(tmpFile string, hashAlgo string) ([]byte, error) {
	var h hash.Hash
	switch strings.ToLower(hashAlgo) {
	case "none":
		return []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}, nil
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	default:
		h = sha256.New()
	}

	f, err := os.Open(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("getSendFileHash %s", err.Error())
	}
	defer f.Close()

	if _, err = io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("getSendFileHash %s", err.Error())
	}

	return padBytes(h.Sum(nil), 32), nil
}
