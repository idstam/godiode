package main

import (
	"bytes"
	"crypto/md5"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	//	"flag"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"log"
	"math"
	"net"
	"os"
	"path"
	"strconv"
	"time"
)

type PendingManifestTransfer struct {
	buff   []byte
	offset int
	index  int
}

type PendingFileTransfer struct {
	size          uint64
	offset        uint64
	index         uint32
	incomplete    bool
	rawSize       uint64
	hash          hash.Hash
	file          *os.File
	transferStart time.Time
	err           *error
	filename      string
	fileIndex     int
	modts         uint32
}

type Receiver struct {
	conf                    *Config
	dir                     string
	tmpDir                  string
	manifest                *Manifest
	manifestId              int
	lastManifestId          int
	pendingFileTransfer     *PendingFileTransfer
	pendingManifestTransfer *PendingManifestTransfer
}

var wg sync.WaitGroup

func (r *Receiver) onFileTransferData(buff []byte, read int) error {
	pt := r.pendingFileTransfer
	if pt == nil || read < 1 || pt.err != nil {
		return nil
	}

	manifestId := binary.BigEndian.Uint32(buff[1:])
	fileIndex := binary.BigEndian.Uint32(buff[5:])
	packageIndex := binary.BigEndian.Uint32(buff[9:])

	if (fileIndex != uint32(pt.fileIndex)) || (manifestId != uint32(r.manifestId)) {
		return errors.New("received package for unexpected manifest or file")
	}
	if packageIndex < pt.index {
		//We're in the expected file, but we're not receiving the packages we want yet.
		return nil
	}

	if packageIndex == pt.index {
		//check out-of-order packets
		if pt.offset+uint64(read-13) > pt.size {
			fmt.Printf("Received package %d", packageIndex)

			err := errors.New("received too much data on file")
			pt.err = &err
			_ = pt.file.Close()
			_ = os.Remove(pt.filename)
			return err
		}
		pt.incomplete = false
		//_, _ = pt.hash.Write(buff[13:read])
		_, _ = pt.file.Write(buff[13:read])

		pt.index++
		r.manifest.Files[fileIndex].NextPackageId = pt.index
		pt.offset += uint64(read - 13)
		pt.rawSize += uint64(HEADER_OVERHEAD + read)
		if pt.offset == uint64(read-13) && r.conf.Verbose {
			//			fmt.Println("Received first byte of data of " + pt.filename)
		}
		if pt.offset == pt.size {
			//done, wait for file Complete packet
		}
	} else {
		//log.Fatal("Received out of order packet ", ptype&0x7F, pt.index, pt.offset)
		err := errors.New(fmt.Sprintf("Received out of order packet for file transfer want %d got %d \n %s \n", pt.index, packageIndex, pt.filename))
		pt.incomplete = true
		pt.err = &err
		_ = pt.file.Close()
		return err
	}
	return nil
}

/*
 * file transfer start packet
 *
 * type - uint8 - 0x02
 * filetype - uint8 - (regular file)
 * manifestSessionId - uint32 - manifest session id
 * fileIndex - uint32 - file index in the manifest
 * Size - uint64 - Size of file in bytes
 * mtime - int64 - unix millis
 * sign - byte[64] - hmac512 of this header
 */
func (r *Receiver) onFileTransferStart(buff []byte, read int) error {
	if read < 1+1+4+4+8+8+64 {
		return errors.New("received truncated file transfer start packet")
	}
	if r.pendingFileTransfer != nil {
		//TODO: check if same file
		_, _ = fmt.Fprintf(os.Stderr, "Received new file transfer with previous still pending\n")
		_ = r.pendingFileTransfer.file.Close()
		r.pendingFileTransfer = nil
	}

	if r.manifest == nil {
		return errors.New("received file transfer start packet without pending manifest")
	}

	if buff[1] != 0 {
		return errors.New("Ignoring file transfer start with unknown file type " + strconv.Itoa(int(buff[2])))
	}

	manifestId := int(binary.BigEndian.Uint32(buff[2:]))
	if manifestId != r.manifestId {
		return errors.New("Ignoring file transfer start for another manifest " + strconv.Itoa(manifestId) + " " + strconv.Itoa(manifestId))
	}

	fileIndex := int(binary.BigEndian.Uint32(buff[6:]))
	if fileIndex < 0 || fileIndex >= len(r.manifest.Files) {
		return errors.New("ignoring file transfer start for invalid file index")
	}

	mf := r.manifest.Files[fileIndex]

	//sanitize Path
	fp := path.Clean(r.dir + mf.Path)
	if fp == "." {
		return errors.New("invalid file Path name")
	}

	size := binary.BigEndian.Uint64(buff[10:])

	if r.conf.HMACSecret != "" {
		h512 := sha512.New()
		_, _ = io.WriteString(h512, r.conf.HMACSecret)
		mac := hmac.New(sha512.New, h512.Sum(nil))
		mac.Write(buff[:26])
		if !bytes.Equal(mac.Sum(nil), buff[26:26+64]) {
			return errors.New("Invalid signature in file start packet for " + fp)
		}
	}
	tmpFile := path.Join(r.tmpDir, "godiodetmp."+strconv.FormatUint(uint64(manifestId), 16)+"."+strconv.Itoa(fileIndex))

	file, err := os.OpenFile(tmpFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, r.conf.Receiver.FilePermission)
	if err != nil {
		return errors.New("Failed to create file " + fp + ": " + err.Error())
	}
	r.pendingFileTransfer = &PendingFileTransfer{
		size:          size,
		hash:          sha256.New(),
		file:          file,
		transferStart: time.Now(),
		filename:      fp,
		fileIndex:     fileIndex,
		modts:         mf.Modts,
		index:         mf.NextPackageId,
	}
	return nil
}

func (r *Receiver) moveTmpFile(pft PendingFileTransfer, tmpFile string, hashFromManifest string) {
	timeTaken := time.Duration.Seconds(time.Since(pft.transferStart))

	if strings.ToLower(r.conf.HashAlgo) != "none" {
		destHash, _ := getFileHash(pft.filename, r.conf.HashAlgo)
		if destHash != nil {
			if hex.EncodeToString(destHash) == hashFromManifest {
				_ = os.Remove(tmpFile)
				if r.conf.Verbose {
					fmt.Println("Received hash matching file. Skip move. " + pft.filename)
				}
				return
			} else {
				_ = os.Remove(pft.filename)
			}
		}
	}
	destDir := filepath.Dir(pft.filename)
	if _, err := os.Stat(destDir); os.IsNotExist(err) {
		_ = os.MkdirAll(destDir, r.conf.Receiver.FolderPermission)
	}

	err := os.Rename(tmpFile, pft.filename)
	if err != nil {
		source, err := os.Open(tmpFile)
		destination, err := os.Create(pft.filename)

		_, err = io.Copy(destination, source)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to move tmp file "+pft.filename+" "+err.Error()+"\n")
			return
		}
		_ = os.Remove(tmpFile)

		_ = source.Close()
		_ = destination.Close()
	}

	err = os.Chtimes(pft.filename, time.Unix(int64(pft.modts), 0), time.Unix(int64(pft.modts), 0))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to set mtime on "+pft.filename+"\n")
	}
	if r.conf.Verbose {
		var speed = 0
		if timeTaken > 0 {
			speed = int(math.Round(float64((8*pft.size)/1000) / timeTaken))
		}
		//h := pft.hash.Sum(nil)
		//fmt.Println("Successfully received " + pft.filename + ", checksum=" + hex.EncodeToString(h) + " Size=" + strconv.FormatInt(int64(pft.size), 10) + " " + strconv.Itoa(speed) + "kbit/s")
		fmt.Println("Successfully received " + pft.filename + ", Size=" + strconv.FormatInt(int64(pft.size), 10) + " " + strconv.Itoa(speed) + "kbit/s")
	}
	return
}

/*
 * file transfer Complete packet
 *
 * type - uint8 - 0x03
 * manifestSessionId - uint32 - manifest session id
 * fileIndex - uint32 - file index in the manifest
 * hash - byte[32] - sha256 of file content
 * sign - byte[64] - hmac512 of this packet
 */
func (r *Receiver) onFileTransferComplete(buff []byte, read int) error {
	if read < 1+4+4+32+64 {
		return errors.New("received truncated file transfer Complete packet")
	}

	pft := r.pendingFileTransfer
	if pft == nil {
		return errors.New("received file transfer Complete packet without pending transfer")
	}

	offset := 1
	manifestId := int(binary.BigEndian.Uint32(buff[offset:]))
	offset += 4
	if manifestId != r.manifestId {
		return errors.New("ignoring file transfer Complete for another manifest " + strconv.Itoa(manifestId) + " " + strconv.Itoa(manifestId))
	}

	fileIndex := int(binary.BigEndian.Uint32(buff[offset:]))
	offset += 4
	if fileIndex != pft.fileIndex {
		return errors.New("ignoring file transfer Complete for other file than the current pending")
	}

	hashFromManifest := hex.EncodeToString(buff[offset : offset+32])
	offset += 32
	if r.conf.HMACSecret != "" {
		h512 := sha512.New()
		_, _ = io.WriteString(h512, r.conf.HMACSecret)
		mac := hmac.New(sha512.New, h512.Sum(nil))
		mac.Write(buff[:offset])
		if !bytes.Equal(mac.Sum(nil), buff[offset:offset+64]) {
			return errors.New("Invalid signature in file Complete packet for file " + pft.filename)
		}
	}
	_ = pft.file.Sync()
	_ = pft.file.Close()

	wg.Add(1)
	go r.finalizeFileTransfer(*pft, manifestId, hashFromManifest)
	r.pendingFileTransfer = nil

	return nil
}

func (r *Receiver) finalizeFileTransfer(pft PendingFileTransfer, manifestId int, hashFromManifest string) {
	if pft.incomplete {
		wg.Done()
		return
	}

	tmpFile := path.Join(r.tmpDir, "godiodetmp."+strconv.FormatUint(uint64(manifestId), 16)+"."+strconv.Itoa(pft.fileIndex))
	fi, err := os.Stat(tmpFile)
	if err == nil {
		if int64(pft.size) != fi.Size() {
			wg.Done()
			return
		}
	}
	tmpHash, err := getFileHash(tmpFile, r.conf.HashAlgo)
	if err != nil {
		wg.Done()
		log.Fatal(err)
	}
	tmpString := hex.EncodeToString(tmpHash)
	if hashFromManifest != tmpString {
		r.manifest.Files[pft.fileIndex].Complete = false
		r.manifest.Files[pft.fileIndex].NextPackageId = 0
		if r.conf.KeepBrokenFiles {
			_ = os.Rename(tmpFile, tmpFile+".broken")
		} else {
			_ = os.Remove(tmpFile)
		}
		fmt.Printf("data checksum error for received file %s \n", pft.filename)

	} else {
		r.manifest.CompletedFilesCount++
		r.manifest.Files[pft.fileIndex].Complete = true
		r.moveTmpFile(pft, tmpFile, hashFromManifest)
	}

	wg.Done()
}

func getFileHash(tmpFile string, hashAlgo string) ([]byte, error) {
	var h hash.Hash
	switch strings.ToLower(hashAlgo) {
	case "none":
		return []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}, nil
	case "md5":
		h = md5.New()
		break
	default:
		h = sha256.New()
	}

	f, err := os.Open(tmpFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if _, err = io.Copy(h, f); err != nil {
		return nil, err
	}
	return padBytes(h.Sum(nil), 32), nil
}
func padBytes(src []byte, blockSize int) []byte {
	if len(src) == blockSize {
		return src
	}
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func (r *Receiver) createFolders() {
	if r.manifest == nil {
		_, _ = fmt.Fprintf(os.Stderr, "no manifest \n")
		return
	}
	for d := range r.manifest.Dirs {
		p := r.dir + path.Clean(r.manifest.Dirs[d].Path)
		err := os.MkdirAll(p, r.conf.Receiver.FolderPermission)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error creating dir "+p+"\n")
		} else {
			err = os.Chtimes(p, time.Unix(int64(r.manifest.Dirs[d].Modts), 0), time.Unix(int64(r.manifest.Dirs[d].Modts), 0))
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Failed to set mtime on "+p+"\n")
			}
		}
	}
	return
}

func (r *Receiver) handleManifestReceived() error {
	if r.conf.Verbose {
		fmt.Println("Received valid manifest with " + strconv.Itoa(len(r.manifest.Dirs)) + " Dirs, " + strconv.Itoa(len(r.manifest.Files)) + " Files")
	}

	saveManifest(r.conf.SaveManifestPath, *r.manifest)

	_, _ = cleanCreateTempDir(r.conf, r.dir)

	if r.conf.Receiver.Delete {
		dm := map[string]bool{}
		fm := map[string]FileRecord{}
		_ = filepath.WalkDir(r.dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if p == r.dir {
				return nil
			}
			if d.IsDir() {
				dm[p] = true
			} else {
				finfo, err := os.Stat(p)
				if err != nil {
					return nil
				}
				fm[p] = FileRecord{DirRecord{p, uint32(finfo.ModTime().Unix())}, finfo.Size(), 0, false}
			}
			return nil
		})
		for i := range r.manifest.Files {
			f, exists := fm[r.manifest.Files[i].Path]
			if exists && f.Size == r.manifest.Files[i].Size && f.Modts == r.manifest.Files[i].Modts {
				//keep this file
				delete(fm, r.manifest.Files[i].Path)
			}
		}
		for f := range fm {
			err := os.Remove(f)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Failed to delete file "+f+"\n")
			} else if r.conf.Verbose {
				fmt.Println("Removed file " + f)
			}
		}

		for i := range r.manifest.Dirs {
			_, exists := dm[r.manifest.Dirs[i].Path]
			if exists {
				//keep this dir
				delete(dm, r.manifest.Dirs[i].Path)
			}
		}
		for d := range dm {
			if d != r.tmpDir {
				err := os.Remove(d)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "Failed to delete dir "+d+"\n")
				} else if r.conf.Verbose {
					fmt.Println("Removed dir " + d)
				}
			}
		}
	}
	go r.createFolders()
	return nil
}

/**
 * manifest record
 * | type | id | part | [Size] | payload
 * type - uint8 - 0x01
 * id - uint32 - manifest session id
 * part - uint32 - manifest session part index
 * Size - uint32 - total manifest Size, only sent in part 0
 * payload | manifest chunk
 *
 */
func (r *Receiver) onManifestPacket(buff []byte, read int) error {
	if read < 10 {
		return nil
	}
	manifestId := int(binary.BigEndian.Uint32(buff[1:]))

	if r.lastManifestId == manifestId {
		//We've already got this manifest.
		return nil
	}
	part := int(binary.BigEndian.Uint32(buff[5:]))
	pmt := r.pendingManifestTransfer
	if pmt != nil {
		if manifestId != r.manifestId {
			_, _ = fmt.Fprintf(os.Stderr, "replacing pending manifest before completed\n")
			r.pendingManifestTransfer = nil
			pmt = nil
		} else {
			if part != pmt.index {
				//r.pendingManifestTransfer = nil
				return errors.New(fmt.Sprintf("received out of order manifest packet got %d wanted %d", part, pmt.index))
			}
			read = copy(pmt.buff[pmt.offset:], buff[9:read])
			pmt.offset += read
			if pmt.offset == len(pmt.buff) {
				manifest, err := deserializeManifest(pmt.buff, r.conf.HMACSecret)
				if err != nil {
					return err
				}
				if r.lastManifestId != manifestId {
					r.manifest = manifest
					err = r.handleManifestReceived()
					if err != nil {
						return err
					}

					r.lastManifestId = manifestId
				}
				return nil
			}
			pmt.index++
		}
	}
	if pmt == nil {
		if part != 0 {
			return errors.New(fmt.Sprintf("waiting for first manifest part, received %d", part))
		}
		size := int(binary.BigEndian.Uint32(buff[9:]))
		if r.conf.Verbose {
			fmt.Println("received manifest size " + strconv.Itoa(size))
		}
		//if size > 5*1024*1024 || size < 1 {
		//	return errors.New("too large manifest")
		//}
		r.manifestId = manifestId
		manifestData := make([]byte, size)
		read = copy(manifestData, buff[13:])
		if read == size {
			manifest, err := deserializeManifest(manifestData, r.conf.HMACSecret)
			if err != nil {
				return err
			}
			if r.lastManifestId != manifestId {
				r.manifest = manifest
				err = r.handleManifestReceived()
				if err != nil {
					return err
				}

				r.lastManifestId = manifestId
			}
			return nil
		}
		r.pendingManifestTransfer = &PendingManifestTransfer{manifestData, read, 1}
		return nil
	}
	return nil
}

/**
 * Protocol format
 *
 * | type | payload... |
 * type - uint8
 *   0x00 - heartbeat
 *   0x01 - manifest
 *   0x02 - file transfer start
 *   0x80-0xFF - file transfer data
 *
 * manifest
 * | type | id | part | [Size] | payload
 * type - uint8 - 0x01
 * id - uint16 - manifest session id
 * part - uint16 - manifest session part index
 * Size - uint32 - total manifest Size (including signature), only sent in part 0
 * payload | <utf8-json> + \n + hmac signature asciihex
 *
 * file transfer start
 * | filename | type | Size | mtime | sign |
 * type - uint8 - 0x02 (regular file)
 * Size - uint64 - Size of file in bytes
 * mtime - uint64 - unix millis
 * sign - byte[64] - hmac512 of this header
 */

func receive(conf *Config, dir string) error {
	wg = sync.WaitGroup{}
	dir = path.Clean(dir) + "/"
	fileInfo, err := os.Stat(dir)
	if err != nil {
		return errors.New("Failed to stat receive dir " + err.Error())
	}
	if !fileInfo.IsDir() {
		return errors.New("receive dir is not a directory")
	}

	tmpDir, err := cleanCreateTempDir(conf, dir)
	if err != nil {
		return err
	}

	maddr, err := net.ResolveUDPAddr("udp", conf.MulticastAddr)
	if err != nil {
		return errors.New("Failed to resolve multicast address: " + err.Error())
	}
	var nic *net.Interface
	if conf.NIC != "" {
		nic, err = net.InterfaceByName(conf.NIC)
		if err != nil {
			return errors.New("Failed to resolve nic: " + err.Error())
		}
	}
	c, err := net.ListenMulticastUDP("udp", nic, maddr)
	if err != nil {
		return errors.New("Failed to join multicast address: " + err.Error())
	}

	err = c.SetReadBuffer(300 * conf.MaxPacketSize)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to set read buffer: "+err.Error()+"\n")
	}

	buff := make([]byte, conf.MaxPacketSize)
	receiver := Receiver{
		conf:   conf,
		dir:    dir,
		tmpDir: tmpDir,
	}

	for {
		read, err := c.Read(buff)
		if err != nil {
			log.Fatal("Failed to receive data: " + err.Error())
		}
		if read < 1 {
			continue
		}
		ptype := buff[0] & 0xFF
		if (ptype & 0x80) != 0 { // file transfer data
			err = receiver.onFileTransferData(buff, read)
		} else if ptype == 0x02 { // start file transfer
			err = receiver.onFileTransferStart(buff, read)
		} else if ptype == 0x03 { // start file transfer
			err = receiver.onFileTransferComplete(buff, read)
		} else if ptype == 0x01 { // manifest
			err = receiver.onManifestPacket(buff, read)
		}
		if err != nil {
			if conf.Verbose {
				_, _ = fmt.Fprintf(os.Stderr, err.Error()+"\n")
			}
		}
		if receiver.manifest != nil && receiver.manifest.CompletedFilesCount > 0 && receiver.manifest.CompletedFilesCount == len(receiver.manifest.Files) {
			fmt.Println("waiting to finalize last file")
			wg.Wait()
			if receiver.manifest.CompletedFilesCount > 0 && receiver.manifest.CompletedFilesCount == len(receiver.manifest.Files) {
				break
			}
		}
	}
	_, _ = cleanCreateTempDir(conf, dir)
	return nil
}

func cleanCreateTempDir(conf *Config, dir string) (string, error) {

	tmpDir := conf.Receiver.TmpDir
	if tmpDir == "" {
		tmpDir = path.Join(dir, ".tmp")
	}
	err := os.Mkdir(tmpDir, 0700)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return "", errors.New("could not create tmp dir")
	}
	fileInfo, err := os.Stat(tmpDir)
	if err != nil {
		return "", errors.New("failed to stat tmp dir " + err.Error())
	}
	if !fileInfo.IsDir() {
		return "", errors.New("tmp dir is not a directory")
	}
	tmpFiles, err := os.ReadDir(tmpDir)
	if err != nil {
		return "", errors.New("failed to read tmp dir " + err.Error())
	}
	for i := range tmpFiles {
		if strings.HasPrefix(tmpFiles[i].Name(), "godiodetmp.") {
			err = os.Remove(path.Join(tmpDir, tmpFiles[i].Name()))
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "failed to remove tmp file: "+tmpFiles[i].Name()+" "+err.Error()+"\n")
			}
		}
	}
	return tmpDir, err
}
