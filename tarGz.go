package mtk

import (
	"archive/tar"
	"compress/gzip"
	"path/filepath"

	"fmt"
	"io"
	"log"
	"os"
	"path"
)

type tarGz struct{}

func NewTarGz() *tarGz {
	return &tarGz{}
}

func (t *tarGz) Archive(inPaths []string, outFilePath string) error {
	// file write
	fw, err := os.Create(outFilePath)
	if err != nil {
		return err
	}
	defer fw.Close()

	// gzip write
	gw := gzip.NewWriter(fw)
	defer gw.Close()

	// tar write
	tw := tar.NewWriter(gw)
	defer tw.Close()

	for i := range inPaths {
		inPaths[i] = path.Clean(inPaths[i])
		// If path does not exists - log error and continue
		if _, err := os.Stat(inPaths[i]); os.IsNotExist(err) {
			log.Printf("ERROR-pathNotExists: %s\n", inPaths[i])
			continue
		}
		if err := t.iterDirectory(inPaths[i], tw); err != nil {
			return err
		}
	}
	return nil
}

func (t *tarGz) ArchiveWriter(inPaths []string, ew io.Writer) error {
	gw := gzip.NewWriter(ew)
	tw := tar.NewWriter(gw)

	defer func() {
		tw.Close()
		gw.Close()
	}()

	for i := range inPaths {
		// inPaths[i] = path.Clean(inPaths[i])
		// inPaths[i] = strings.ReplaceAll(inPaths[i], "\\", "/")
		// If path does not exists - log error and continue
		if _, err := os.Stat(inPaths[i]); os.IsNotExist(err) {
			log.Printf("ERROR-pathNotExists: %s\n", inPaths[i])
			continue
		}
		if err := t.iterDirectory(inPaths[i], tw); err != nil {
			return err
		}
	}
	return nil
}

func (t *tarGz) iterDirectory(dirPath string, tw *tar.Writer) error {
	dir, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	defer dir.Close()

	fis, err := dir.Readdir(0)
	if err != nil {
		return err
	}

	for _, fi := range fis {
		curPath := filepath.Join(dirPath, fi.Name())
		if fi.IsDir() {
			t.iterDirectory(curPath, tw)
		} else {
			fmt.Printf("adding... %s\n", curPath)
			if err := t.tarGzWrite(curPath, tw, fi); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *tarGz) tarGzWrite(_path string, tw *tar.Writer, fi os.FileInfo) error {
	fr, err := os.Open(_path)
	if err != nil {
		return err
	}
	defer fr.Close()

	h := new(tar.Header)
	h.Name = _path
	h.Size = fi.Size()
	h.Mode = int64(fi.Mode())
	h.ModTime = fi.ModTime()

	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	if _, err := io.Copy(tw, fr); err != nil {
		return err
	}
	return nil
}
