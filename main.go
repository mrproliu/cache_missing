package main

import (
	"cache_missing/bpf"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

const watchDirectory = "/tmp"

func main() {
	// mock file cache
	files := make([]*os.File, 0, 10)
	for i := range 10 {
		path := fmt.Sprintf("%s/cache%d.txt", watchDirectory, i)
		file, err := os.OpenFile(path, os.O_CREATE, 0644)
		if err != nil {
			log.Fatal("Error creating file:", err)
		}
		files = append(files, file)
	}
	defer func() {
		for i := range files {
			_ = files[i].Close()
		}
	}()
	// mock write file
	go func() {
		i := 0
		for {
			inx := i % 10
			files[inx].WriteString(fmt.Sprintf("wring_%d", time.Now().Unix()))
			time.Sleep(time.Second * 1)
			i++
		}
	}()
	// mock read file
	go func() {
		i := 0
		for {
			inx := i % 10
			_, _ = files[inx].Read(make([]byte, 1024))
			_, _ = files[inx].Seek(0, io.SeekStart)
			fd := int(files[inx].Fd())

			// clean the page cache, next read will increase minor fault
			err := unix.Fadvise(fd, 0, 0, unix.FADV_DONTNEED)
			if err != nil {
				fmt.Println("fadvise error:", err)
			}
			time.Sleep(time.Millisecond * 300)
			i++
		}
	}()

	// running BPF to monitoring
	staticSupplier, err := bpf.Run(func(f func(fd int, isAdd bool)) {
		go func() {
			// monitor file changes
			monitorFDChanges(f, watchDirectory)
		}()
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
	go func() {
		for {
			statics := staticSupplier()
			fmt.Printf("file statics, mark access: %d,\tminor faults: %d,\tmajor faults: %d, hit rate: %f\n",
				statics.MarkAccessCount, statics.MinorFaultCount, statics.MajorFaultCount, statics.CalcHitRate())
			time.Sleep(time.Second)
		}
	}()

	<-make(chan struct{}, 1)
}

func monitorFDChanges(callback func(fd int, isAdd bool), watchDir string) {
	// tmp using the list FDs in /proc/<pid>/fd
	latestFDMap := make(map[int]bool)
	for {
		currentFDMap := make(map[int]bool)
		fdDir := fmt.Sprintf("/proc/%d/fd", os.Getpid())
		files, err := os.ReadDir(fdDir)
		if err != nil {
			log.Fatal("Error reading directory:", err)
		}
		for _, file := range files {
			readlink, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, file.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(readlink, watchDirectory) {
				fd, _ := strconv.ParseInt(file.Name(), 10, 64)
				currentFDMap[int(fd)] = true
			}
		}

		// find which fd need to be added
		for fd := range currentFDMap {
			if !latestFDMap[fd] {
				log.Println("detect add new monitoring fd: ", fd)
				callback(fd, true)
			}
		}

		// find which fd need to be deleted
		for fd := range latestFDMap {
			if !currentFDMap[fd] {
				log.Println("detect delete monitoring fd: ", fd)
				callback(fd, false)
			}
		}
		latestFDMap = currentFDMap

		time.Sleep(time.Second * 1)
	}
}
