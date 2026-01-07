/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package blkiorun

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"

	"github.com/containerd/log"
)

const (
	// BFQ IO weight range: 10-1000
	bfqWeightMin = 10
	bfqWeightMax = 1000

	// io.weight range: 1-10000
	ioWeightMax = 10000

	// Default normal BFQ weight
	normalBFQWeight = 100

	// Default systemd slice name
	defaultSliceName = "containerdio.slice"

	// Timeout for systemd operations
	systemdTimeout = 5 * time.Second
)

var (
	state     *globalState
	stateOnce sync.Once
	counter   uint64

	// ErrNotInitialized is returned when blkiorun is not initialized
	ErrNotInitialized = errors.New("blkiorun not initialized, call Init first")
)

// globalState stores the IO weight control state
type globalState struct {
	slicePath      string // cgroup path for the slice
	containerdPath string // containerd's cgroup path
	weight         uint16 // configured weight
	initialized    bool
}

// Init initializes block IO weight control for containerd.
// Parameters:
// - weight: IO weight value (10-1000). Set to 0 to disable.
// - slicePath: Path to existing cgroup (optional, uses systemd if empty)
// - sliceName: Systemd slice name (default: "containerdio.slice")
func Init(weight int, slicePath, sliceName string) error {
	var initErr error

	stateOnce.Do(func() {
		s := &globalState{}

		if weight <= 0 {
			log.L.Debug("blkiorun: disabled (weight=0)")
			state = s
			return
		}

		if weight < bfqWeightMin || weight > bfqWeightMax {
			log.L.Warnf("blkiorun: weight %d out of range [%d, %d], disabled", weight, bfqWeightMin, bfqWeightMax)
			state = s
			return
		}

		s.weight = uint16(weight)
		log.L.Infof("blkiorun: weight configured: %d", weight)

		if !isCgroupV2() {
			log.L.Warn("blkiorun: cgroups v2 not available, disabled")
			state = s
			return
		}

		// Get containerd's cgroup path
		var err error
		s.containerdPath, err = getCurrentCgroupPath()
		if err != nil {
			initErr = fmt.Errorf("failed to get cgroup path: %w", err)
			state = s
			return
		}
		log.L.Debugf("blkiorun: containerd cgroup: %s", s.containerdPath)

		var cgroupPath string
		if slicePath != "" {
			cgroupPath = slicePath
			log.L.Debugf("blkiorun: using configured path: %s", cgroupPath)
		} else {
			// Create systemd slice
			if sliceName == "" {
				sliceName = defaultSliceName
			}
			if !strings.HasSuffix(sliceName, ".slice") {
				sliceName += ".slice"
			}

			ctx, cancel := context.WithTimeout(context.Background(), systemdTimeout)
			defer cancel()

			if err := createSlice(ctx, sliceName); err != nil {
				log.L.WithError(err).Warnf("blkiorun: failed to create slice %s", sliceName)
				state = s
				return
			}

			cgroupPath = sliceCgroupPath(sliceName)
			for i := 0; i < 10; i++ {
				if _, err := os.Stat(cgroupPath); err == nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}

		// Verify io.weight is available
		if _, err := os.Stat(filepath.Join(cgroupPath, "io.weight")); os.IsNotExist(err) {
			log.L.Warn("blkiorun: io.weight not available")
			state = s
			return
		}

		// Enable io controller for children
		if err := enableIOController(cgroupPath); err != nil {
			log.L.WithError(err).Warn("blkiorun: failed to enable io controller")
			state = s
			return
		}

		s.slicePath = cgroupPath
		s.initialized = true
		state = s
		log.L.Infof("blkiorun: initialized at %s", cgroupPath)
	})

	return initErr
}

// IsInitialized returns true if blkiorun is initialized
func IsInitialized() bool {
	return state != nil && state.initialized
}

// Go executes fn in a new goroutine with configured IO weight.
// The OS thread is discarded after fn completes.
func Go[T any](fn func() (T, error)) (T, error) {
	if !IsInitialized() {
		return fn()
	}
	return GoWithConfig(state.weight, fn)
}

// GoWithConfig executes fn in a new goroutine with specified IO weight.
func GoWithConfig[T any](weight uint16, fn func() (T, error)) (T, error) {
	if weight == 0 || !IsInitialized() {
		return fn()
	}

	type result struct {
		value T
		err   error
	}

	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()

		cg, err := createCgroup(weight)
		if err != nil {
			log.L.WithError(err).Debug("blkiorun: failed to create cgroup")
			v, err := fn()
			ch <- result{v, err}
			return
		}
		defer func() {
			cg.leave()
			cg.destroy()
		}()

		if err := cg.enter(); err != nil {
			log.L.WithError(err).Debug("blkiorun: failed to enter cgroup")
			v, err := fn()
			ch <- result{v, err}
			return
		}

		v, err := fn()
		ch <- result{v, err}
	}()

	res := <-ch
	return res.value, res.err
}

// Local executes fn in current goroutine with configured IO weight.
func Local[T any](fn func() (T, error)) (T, error) {
	if !IsInitialized() {
		return fn()
	}
	return LocalWithConfig(state.weight, fn)
}

// LocalWithConfig executes fn in current goroutine with specified IO weight.
func LocalWithConfig[T any](weight uint16, fn func() (T, error)) (T, error) {
	if weight == 0 || !IsInitialized() {
		return fn()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cg, err := createCgroup(weight)
	if err != nil {
		log.L.WithError(err).Debug("blkiorun: failed to create cgroup")
		return fn()
	}
	defer func() {
		cg.leave()
		cg.destroy()
	}()

	if err := cg.enter(); err != nil {
		log.L.WithError(err).Debug("blkiorun: failed to enter cgroup")
		return fn()
	}

	return fn()
}

// cgroup represents a temporary cgroup for IO weight control
type cgroup struct {
	path string
}

func createCgroup(weight uint16) (*cgroup, error) {
	if state == nil || !state.initialized {
		return nil, ErrNotInitialized
	}

	id := atomic.AddUint64(&counter, 1)
	path := filepath.Join(state.slicePath, fmt.Sprintf("blkio-%d-%d", os.Getpid(), id))

	if err := os.Mkdir(path, 0755); err != nil {
		return nil, err
	}

	cg := &cgroup{path: path}
	if err := cg.setWeight(weight); err != nil {
		cg.destroy()
		return nil, err
	}

	return cg, nil
}

func (cg *cgroup) setWeight(weight uint16) error {
	// Convert BFQ weight to io.weight
	ioWeight := 1 + (uint64(weight)-10)*9999/990
	return os.WriteFile(filepath.Join(cg.path, "io.weight"), []byte(strconv.FormatUint(ioWeight, 10)), 0644)
}

func (cg *cgroup) enter() error {
	return os.WriteFile(filepath.Join(cg.path, "cgroup.procs"), []byte(strconv.Itoa(syscall.Gettid())), 0644)
}

func (cg *cgroup) leave() error {
	if state == nil {
		return nil
	}
	return os.WriteFile(filepath.Join(state.containerdPath, "cgroup.procs"), []byte(strconv.Itoa(syscall.Gettid())), 0644)
}

func (cg *cgroup) destroy() {
	os.Remove(cg.path)
}

// Helper functions

func isCgroupV2() bool {
	stat, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil && !stat.IsDir()
}

func getCurrentCgroupPath() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 3)
		if len(parts) == 3 && parts[0] == "0" {
			p := parts[2]
			if p == "" {
				p = "/"
			}
			return filepath.Join("/sys/fs/cgroup", p), nil
		}
	}
	return "", errors.New("cgroup v2 path not found")
}

func enableIOController(path string) error {
	ctrl := filepath.Join(path, "cgroup.subtree_control")
	data, _ := os.ReadFile(ctrl)
	if strings.Contains(string(data), "io") {
		return nil
	}
	return os.WriteFile(ctrl, []byte("+io"), 0644)
}

func createSlice(ctx context.Context, name string) error {
	conn, err := systemdDbus.NewWithContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	props := []systemdDbus.Property{
		systemdDbus.PropDescription("Containerd IO Weight Control"),
		{Name: "DefaultDependencies", Value: dbus.MakeVariant(false)},
		{Name: "IOAccounting", Value: dbus.MakeVariant(true)},
	}

	ch := make(chan string, 1)
	_, err = conn.StartTransientUnitContext(ctx, name, "replace", props, ch)
	if err != nil {
		if strings.Contains(err.Error(), "already") || strings.Contains(err.Error(), "loaded") {
			return nil
		}
		return err
	}

	select {
	case <-ch:
	case <-time.After(systemdTimeout):
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func sliceCgroupPath(name string) string {
	n := strings.TrimSuffix(name, ".slice")
	parts := strings.Split(n, "-")
	if len(parts) == 1 {
		return filepath.Join("/sys/fs/cgroup", name)
	}
	var pp []string
	for i := 1; i <= len(parts); i++ {
		pp = append(pp, strings.Join(parts[:i], "-")+".slice")
	}
	return filepath.Join("/sys/fs/cgroup", filepath.Join(pp...))
}
