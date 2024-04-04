package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/gobwas/glob"
)

type DirRecord struct {
	Path  string
	Modts uint32
}

type FileRecord struct {
	DirRecord
	Size          int64
	NextPackageId uint32
	Complete      bool
}

type Manifest struct {
	Dirs                []DirRecord
	Files               []FileRecord
	CompletedFilesCount int
}

/**
 * Manifest format
 * <number of Dirs> | <dir-records> | <file records> | <signature>
 * number of Dirs - uint32 - number of directory records
 * number of Files - uint32 - number of file records
 * dir-records:
 *		len uint16 - Path string length
 *      Path string - Path of the dir
 *      Modts uint32 - the modification ts of the folder (unix epoch seconds)
 * file-records:
 *		len uint16 - Path string length
 *      Path string - Path of the file
 *      Modts uint32 - the modification ts of the folder (unix epoch seconds)
 *      Size uint64 - Size of the file in bytes
 * signature byte[64] - hmac512 of this packet
 */
func deserializeManifest(data []byte, conf *Config) (*Manifest, error) {
	hmacSecret := conf.HMACSecret

	l := len(data)
	if l < 64+4+4 {
		return nil, errors.New("truncated manifest")
	}
	h512 := sha512.New()
	io.WriteString(h512, hmacSecret)
	mac := hmac.New(sha512.New, h512.Sum(nil))
	mac.Write(data[:l-64])
	sign := mac.Sum(nil)

	if !bytes.Equal(sign, data[l-64:]) {
		if conf.SaveManifestPath != "" {
			err := os.WriteFile(conf.SaveManifestPath+".bin", data, 0644)
			if err != nil {
				return nil, err
			}
		}

		return nil, errors.New("invalid manifest signature")
	}

	manifest := Manifest{}
	dl := int(binary.BigEndian.Uint32(data[0:]))
	fl := int(binary.BigEndian.Uint32(data[4:]))

	offset := 8
	//TODO: check lengths
	manifest.Dirs = make([]DirRecord, dl)
	manifest.Files = make([]FileRecord, fl)
	for i := 0; i < dl; i++ {
		plen := int(binary.BigEndian.Uint16(data[offset:]) & 0xFFFF)
		offset += 2
		//TODO: check lengths
		p := string(data[offset : offset+plen])
		offset += plen
		modts := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		manifest.Dirs[i] = DirRecord{p, modts}
	}
	for i := 0; i < fl; i++ {
		plen := int(binary.BigEndian.Uint16(data[offset:]) & 0xFFFF)
		offset += 2
		//TODO: check lengths
		p := string(data[offset : offset+plen])
		offset += plen
		modts := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		s := binary.BigEndian.Uint64(data[offset:])
		offset += 8
		manifest.Files[i] = FileRecord{DirRecord{p, modts}, int64(s), 0, false}
	}
	return &manifest, nil
}

func (m *Manifest) serializeManifest(conf *Config) ([]byte, error) {
	hmacSecret := conf.HMACSecret
	dirsSize := 0
	filesSize := 0
	for i := range m.Dirs {
		dirsSize += 2 + len(m.Dirs[i].Path) + 4
	}
	for i := range m.Files {
		filesSize += 2 + len(m.Files[i].Path) + 4 + 8
	}
	manifest := make([]byte, 4+4+dirsSize+filesSize+64)
	binary.BigEndian.PutUint32(manifest, uint32(len(m.Dirs)))
	binary.BigEndian.PutUint32(manifest[4:], uint32(len(m.Files)))
	offset := 8

	for i := range m.Dirs {
		d := m.Dirs[i]
		binary.BigEndian.PutUint16(manifest[offset:], uint16(len(d.Path)))
		offset += 2
		copy(manifest[offset:], d.Path)
		offset += len(d.Path)
		binary.BigEndian.PutUint32(manifest[offset:], d.Modts)
		offset += 4
	}
	for i := range m.Files {
		f := m.Files[i]
		binary.BigEndian.PutUint16(manifest[offset:], uint16(len(f.Path)))
		offset += 2
		copy(manifest[offset:], f.Path)
		offset += len(f.Path)
		binary.BigEndian.PutUint32(manifest[offset:], f.Modts)
		offset += 4
		binary.BigEndian.PutUint64(manifest[offset:], uint64(f.Size))
		offset += 8
	}

	h512 := sha512.New()
	io.WriteString(h512, hmacSecret)
	mac := hmac.New(sha512.New, h512.Sum(nil))
	mac.Write(manifest[:offset])
	sign := mac.Sum(nil)
	copy(manifest[offset:], sign)

	if conf.SaveManifestPath != "" {
		err := os.WriteFile(conf.SaveManifestPath+".bin", manifest, 0644)
		if err != nil {
			return nil, err
		}
	}
	return manifest, nil

}

func generateManifest(dir string, manifestPath string, include arrayFlags, exclude arrayFlags) (*Manifest, error) {
	manifest := Manifest{make([]DirRecord, 0), make([]FileRecord, 0), 0}
	dir = path.Clean(dir)
	finfo, err := os.Stat(dir)
	includeGlobs, _ := compileGlobs(include)
	excludeGlobs, _ := compileGlobs(exclude)

	if err != nil {
		return nil, err
	}

	if finfo.IsDir() {
		dir = dir + "/"
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if p == dir {
				return nil
			}

			p = strings.Replace(p, dir, "", 1)
			if d.IsDir() {
				info, err := d.Info()
				if err != nil {
					return nil
				}
				manifest.Dirs = append(manifest.Dirs, DirRecord{p, uint32(info.ModTime().Unix())})
			} else {
				finfo, err := d.Info()
				if err != nil {
					return nil
				}

				matchesExclude := matchAnyGlob(excludeGlobs, p, false)
				matchesInclude := matchAnyGlob(includeGlobs, p, true)
				if matchesInclude && !matchesExclude {
					manifest.Files = append(manifest.Files, FileRecord{DirRecord{p, uint32(finfo.ModTime().Unix())}, finfo.Size(), 0, false})
				}

			}
			return nil
		})
	} else {
		fname := finfo.Name()
		matchesExclude := matchAnyGlob(excludeGlobs, fname, false)
		matchesInclude := matchAnyGlob(includeGlobs, fname, true)
		if matchesInclude && !matchesExclude {
			manifest.Files = append(manifest.Files, FileRecord{DirRecord{fname, uint32(finfo.ModTime().Unix())}, finfo.Size(), 0, false})
		}
	}

	saveManifest(manifestPath, manifest)
	return &manifest, nil
}

func saveManifest(manifestPath string, manifest Manifest) {

	fileData, err := json.MarshalIndent(manifest, "", " ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "saveManifest: "+err.Error()+"\n")
		fmt.Println("saveManifest: " + err.Error())
		return
	}

	err = os.WriteFile(manifestPath, fileData, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "saveManifest: "+err.Error()+"\n")
		fmt.Println("saveManifest: " + err.Error())
		return
	}

}

func compileGlobs(patterns arrayFlags) ([]glob.Glob, error) {
	ret := make([]glob.Glob, 0)
	for _, p := range patterns {
		ret = append(ret, glob.MustCompile(p))
	}
	return ret, nil
}
func matchAnyGlob(globs []glob.Glob, fileName string, defaultOnEmpty bool) bool {
	if len(globs) == 0 {
		return defaultOnEmpty
	}

	for _, g := range globs {
		if g.Match(fileName) {
			return true
		}
	}
	return false
}
