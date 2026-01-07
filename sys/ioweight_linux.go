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

package sys

import (
	"bufio"
	"bytes"
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

	"github.com/containerd/log"
)

// IOWeightEnvKey is the environment variable key to set IO weight
// for image pull, unpack, and commit operations.
// Set to a value in range [10, 1000] to enable IO weight control.
const IOWeightEnvKey = "CONTAINERD_IO_WEIGHT"

const (
	// IO weight range for io.weight (cgroups v2): 1-10000
	ioWeightMax = 10000

	// BFQ IO weight range for io.bfq.weight: 10-1000
	bfqWeightMin = 10
	bfqWeightMax = 1000

	// Default normal BFQ weight
	normalBFQWeight = 100
)

var (
	// cgroupV2Enabled indicates if cgroups v2 is available
	cgroupV2Enabled     bool
	cgroupV2EnabledOnce sync.Once

	// bfqSupported indicates if BFQ IO scheduler is available
	bfqSupported     bool
	bfqSupportedOnce sync.Once

	// configuredIOWeight stores the configured IO weight from environment variable
	// 0 means not configured/disabled
	configuredIOWeight     uint16
	configuredIOWeightOnce sync.Once

	// ioweightCgroupCounter is used to generate unique child cgroup names
	ioweightCgroupCounter uint64
)

// getConfiguredIOWeight returns the configured IO weight from environment variable.
// Returns 0 if not configured or invalid.
func getConfiguredIOWeight() uint16 {
	configuredIOWeightOnce.Do(func() {
		val := os.Getenv(IOWeightEnvKey)
		if val == "" {
			log.L.Debug("IO weight not configured via environment variable")
			return
		}

		weight, err := strconv.ParseUint(val, 10, 16)
		if err != nil {
			log.L.WithError(err).Warnf("Invalid IO weight value: %s", val)
			return
		}

		// Validate range
		if weight < bfqWeightMin || weight > bfqWeightMax {
			log.L.Warnf("IO weight %d out of valid range [%d, %d], ignoring", weight, bfqWeightMin, bfqWeightMax)
			return
		}

		configuredIOWeight = uint16(weight)
		log.L.Infof("IO weight configured: %d (from %s)", configuredIOWeight, IOWeightEnvKey)
	})
	return configuredIOWeight
}

// isCgroupV2Enabled checks if cgroups v2 is enabled on the system.
func isCgroupV2Enabled() bool {
	cgroupV2EnabledOnce.Do(func() {
		// Check if cgroup2 filesystem is mounted at /sys/fs/cgroup
		if stat, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil && !stat.IsDir() {
			cgroupV2Enabled = true
			log.L.Debug("cgroups v2 detected")
		} else {
			log.L.Debug("cgroups v2 not available")
		}
	})
	return cgroupV2Enabled
}

// isBFQSupported checks if BFQ IO scheduler is supported.
func isBFQSupported() bool {
	bfqSupportedOnce.Do(func() {
		if !isCgroupV2Enabled() {
			return
		}

		cgroupPath, err := getCurrentCgroupPath()
		if err != nil {
			log.L.WithError(err).Debug("Failed to get cgroup path for BFQ check")
			return
		}

		bfqPath := filepath.Join(cgroupPath, "io.bfq.weight")
		if _, err := os.Stat(bfqPath); err == nil {
			bfqSupported = true
			log.L.Debugf("BFQ IO scheduler supported at %s", bfqPath)
		} else {
			log.L.Debugf("BFQ IO scheduler not available, will use io.weight")
		}
	})
	return bfqSupported
}

// getCurrentCgroupPath returns the current process's cgroup v2 path.
func getCurrentCgroupPath() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		// cgroup v2 format: 0::/path
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" {
			cgroupPath := parts[2]
			if cgroupPath == "" {
				cgroupPath = "/"
			}
			return filepath.Join("/sys/fs/cgroup", cgroupPath), nil
		}
	}
	return "", errors.New("cgroup v2 path not found")
}

// readIOWeight reads the current IO weight from cgroups.
// Returns BFQ weight if available, otherwise io.weight converted to BFQ range.
func readIOWeight() (uint16, error) {
	if !isCgroupV2Enabled() {
		return 0, errors.New("cgroups v2 not enabled")
	}

	cgroupPath, err := getCurrentCgroupPath()
	if err != nil {
		return 0, err
	}

	// Try BFQ first
	if isBFQSupported() {
		data, err := os.ReadFile(filepath.Join(cgroupPath, "io.bfq.weight"))
		if err == nil {
			// BFQ weight format: "default <weight>" or just "<weight>"
			fields := strings.Fields(string(bytes.TrimSpace(data)))
			if len(fields) > 0 {
				// Parse the last field as the weight
				weight, err := strconv.ParseUint(fields[len(fields)-1], 10, 16)
				if err == nil {
					return uint16(weight), nil
				}
			}
		}
	}

	// Fallback to io.weight
	data, err := os.ReadFile(filepath.Join(cgroupPath, "io.weight"))
	if err != nil {
		return normalBFQWeight, nil // Return default if reading fails
	}

	fields := strings.Fields(string(bytes.TrimSpace(data)))
	if len(fields) > 0 {
		// Parse the last field as the weight
		ioWeight, err := strconv.ParseUint(fields[len(fields)-1], 10, 64)
		if err == nil {
			// Convert io.weight (1-10000) back to BFQ weight (10-1000)
			return convertIOWeightToBFQ(ioWeight), nil
		}
	}

	return normalBFQWeight, nil
}

// writeIOWeight writes IO weight to cgroups.
// Uses io.bfq.weight if available, otherwise io.weight with conversion.
func writeIOWeight(weight uint16) error {
	if !isCgroupV2Enabled() {
		return errors.New("cgroups v2 not enabled")
	}

	if weight < bfqWeightMin || weight > bfqWeightMax {
		return fmt.Errorf("weight %d out of range [%d, %d]", weight, bfqWeightMin, bfqWeightMax)
	}

	cgroupPath, err := getCurrentCgroupPath()
	if err != nil {
		return err
	}

	// Try BFQ first
	if isBFQSupported() {
		bfqPath := filepath.Join(cgroupPath, "io.bfq.weight")
		if err := os.WriteFile(bfqPath, []byte(strconv.FormatUint(uint64(weight), 10)), 0644); err == nil {
			log.L.Debugf("Set io.bfq.weight to %d at %s", weight, bfqPath)
			return nil
		}
	}

	// Fallback to io.weight with conversion
	ioWeight := convertBFQToIOWeight(weight)
	ioWeightPath := filepath.Join(cgroupPath, "io.weight")
	if err := os.WriteFile(ioWeightPath, []byte(strconv.FormatUint(ioWeight, 10)), 0644); err != nil {
		log.L.WithError(err).Debugf("Failed to write io.weight at %s", ioWeightPath)
		return err
	}
	log.L.Debugf("Set io.weight to %d (from BFQ weight %d) at %s", ioWeight, weight, ioWeightPath)
	return nil
}

// convertBFQToIOWeight converts BFQ weight (10-1000) to io.weight (1-10000).
// This is the same conversion used by runc.
func convertBFQToIOWeight(bfqWeight uint16) uint64 {
	if bfqWeight == 0 {
		return 0
	}
	return 1 + (uint64(bfqWeight)-10)*9999/990
}

// convertIOWeightToBFQ converts io.weight (1-10000) back to BFQ weight (10-1000).
func convertIOWeightToBFQ(ioWeight uint64) uint16 {
	if ioWeight == 0 {
		return 0
	}
	if ioWeight <= 1 {
		return bfqWeightMin
	}
	if ioWeight >= ioWeightMax {
		return bfqWeightMax
	}
	// Reverse the conversion: bfqWeight = 10 + (ioWeight - 1) * 990 / 9999
	return uint16(10 + (ioWeight-1)*990/9999)
}

// ioWeightCgroup represents a child cgroup for IO weight control
type ioWeightCgroup struct {
	path         string // Full path to the child cgroup
	originalPath string // Full path to the original cgroup (to return thread to)
}

// checkIOControllerEnabled checks if the io controller is enabled in a cgroup's subtree_control
func checkIOControllerEnabled(cgroupPath string) bool {
	subtreeControlPath := filepath.Join(cgroupPath, "cgroup.subtree_control")
	data, err := os.ReadFile(subtreeControlPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "io")
}

// findParentWithIOController finds a parent cgroup that has io controller enabled in subtree_control.
// Due to cgroups v2 "no internal processes" constraint, we cannot enable subtree controllers
// in a cgroup that has processes. So we look for a parent cgroup that already has io enabled.
func findParentWithIOController(startPath string) (string, error) {
	path := startPath
	cgroupRoot := "/sys/fs/cgroup"

	for path != cgroupRoot && path != "/" {
		parentPath := filepath.Dir(path)
		if checkIOControllerEnabled(parentPath) {
			log.L.Debugf("Found parent with io controller enabled: %s", parentPath)
			return parentPath, nil
		}
		path = parentPath
	}

	return "", errors.New("no parent cgroup with io controller enabled found")
}

// tryEnableIOController attempts to enable io controller in a cgroup's subtree_control.
// Returns true if successful or already enabled, false if failed (e.g., due to processes in cgroup).
func tryEnableIOController(cgroupPath string) bool {
	if checkIOControllerEnabled(cgroupPath) {
		return true
	}
	subtreeControlPath := filepath.Join(cgroupPath, "cgroup.subtree_control")
	if err := os.WriteFile(subtreeControlPath, []byte("+io"), 0644); err != nil {
		log.L.Debugf("Cannot enable io controller in %s: %v", cgroupPath, err)
		return false
	}
	log.L.Debugf("Enabled io controller in %s", subtreeControlPath)
	return true
}

// createIOWeightCgroup creates a child cgroup for IO weight control.
// It first tries to create in the current cgroup (if io controller can be enabled),
// otherwise falls back to a parent that already has io controller enabled.
func createIOWeightCgroup(weight uint16) (*ioWeightCgroup, error) {
	if !isCgroupV2Enabled() {
		return nil, errors.New("cgroups v2 not enabled")
	}

	originalPath, err := getCurrentCgroupPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get current cgroup path: %w", err)
	}

	// First, try to enable io controller in current cgroup (works if Delegate= is configured)
	var parentPath string
	if tryEnableIOController(originalPath) {
		parentPath = originalPath
		log.L.Debugf("Using current cgroup as parent: %s", parentPath)
	} else {
		// Fall back to finding a parent cgroup that already has io controller enabled
		parentPath, err = findParentWithIOController(originalPath)
		if err != nil {
			return nil, fmt.Errorf("failed to find parent with io controller: %w", err)
		}
	}

	// Generate unique child cgroup name with process id to avoid conflicts
	id := atomic.AddUint64(&ioweightCgroupCounter, 1)
	childName := fmt.Sprintf("ioweight-%d-%d", os.Getpid(), id)
	childPath := filepath.Join(parentPath, childName)

	// Create the child cgroup directory
	if err := os.Mkdir(childPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create child cgroup %s: %w", childPath, err)
	}

	log.L.Debugf("Created child cgroup: %s (will return to %s)", childPath, originalPath)

	cg := &ioWeightCgroup{
		path:         childPath,
		originalPath: originalPath,
	}

	// Set IO weight on the child cgroup
	if err := cg.setIOWeight(weight); err != nil {
		// Clean up on failure
		cg.destroy()
		return nil, fmt.Errorf("failed to set IO weight on child cgroup: %w", err)
	}

	return cg, nil
}

// setIOWeight sets the IO weight on this cgroup
func (cg *ioWeightCgroup) setIOWeight(weight uint16) error {
	if weight < bfqWeightMin || weight > bfqWeightMax {
		return fmt.Errorf("weight %d out of range [%d, %d]", weight, bfqWeightMin, bfqWeightMax)
	}

	// Try BFQ first
	if isBFQSupported() {
		bfqPath := filepath.Join(cg.path, "io.bfq.weight")
		if err := os.WriteFile(bfqPath, []byte(strconv.FormatUint(uint64(weight), 10)), 0644); err == nil {
			log.L.Debugf("Set io.bfq.weight to %d at %s", weight, bfqPath)
			return nil
		}
	}

	// Fallback to io.weight with conversion
	ioWeight := convertBFQToIOWeight(weight)
	ioWeightPath := filepath.Join(cg.path, "io.weight")
	if err := os.WriteFile(ioWeightPath, []byte(strconv.FormatUint(ioWeight, 10)), 0644); err != nil {
		return fmt.Errorf("failed to write io.weight: %w", err)
	}
	log.L.Debugf("Set io.weight to %d (from BFQ weight %d) at %s", ioWeight, weight, ioWeightPath)
	return nil
}

// enter moves the current thread into this cgroup
func (cg *ioWeightCgroup) enter() error {
	tid := syscall.Gettid()
	procsPath := filepath.Join(cg.path, "cgroup.procs")
	if err := os.WriteFile(procsPath, []byte(strconv.Itoa(tid)), 0644); err != nil {
		return fmt.Errorf("failed to move thread %d to cgroup %s: %w", tid, cg.path, err)
	}
	log.L.Debugf("Moved thread %d to child cgroup %s", tid, cg.path)
	return nil
}

// leave moves the current thread back to the original cgroup
func (cg *ioWeightCgroup) leave() error {
	tid := syscall.Gettid()
	procsPath := filepath.Join(cg.originalPath, "cgroup.procs")
	if err := os.WriteFile(procsPath, []byte(strconv.Itoa(tid)), 0644); err != nil {
		return fmt.Errorf("failed to move thread %d back to original cgroup %s: %w", tid, cg.originalPath, err)
	}
	log.L.Debugf("Moved thread %d back to original cgroup %s", tid, cg.originalPath)
	return nil
}

// destroy removes this cgroup
func (cg *ioWeightCgroup) destroy() {
	if err := os.Remove(cg.path); err != nil {
		log.L.WithError(err).Debugf("Failed to remove child cgroup %s", cg.path)
	} else {
		log.L.Debugf("Removed child cgroup %s", cg.path)
	}
}

// RunWithIOWeightValue runs the given function in a dedicated OS thread
// with the specified IO weight via a child cgroup with io.weight/io.bfq.weight.
// If weight is 0, the function runs without IO weight adjustment.
// This function blocks until fn completes.
// The dedicated OS thread is terminated after fn returns.
// A temporary child cgroup is created for the operation and cleaned up after completion.
func RunWithIOWeightValue[T any](weight uint16, fn func() (T, error)) (T, error) {
	if weight == 0 {
		return fn()
	}

	log.L.Debugf("RunWithIOWeightValue: starting with weight=%d", weight)

	type result struct {
		value T
		err   error
	}

	resCh := make(chan result, 1)

	go func() {
		// we discard this OS thread after use
		runtime.LockOSThread()

		// Create child cgroup with specified IO weight
		cg, err := createIOWeightCgroup(weight)
		if err != nil {
			log.L.WithError(err).Debug("Failed to create IO weight cgroup, running without IO weight control")
			v, err := fn()
			resCh <- result{value: v, err: err}
			return
		}
		defer func() {
			// Leave the child cgroup and destroy it
			if err := cg.leave(); err != nil {
				log.L.WithError(err).Debug("Failed to leave child cgroup")
			}
			cg.destroy()
		}()

		// Enter the child cgroup
		if err := cg.enter(); err != nil {
			log.L.WithError(err).Debug("Failed to enter child cgroup, running without IO weight control")
			v, err := fn()
			resCh <- result{value: v, err: err}
			return
		}

		v, err := fn()
		resCh <- result{value: v, err: err}
	}()

	res := <-resCh
	log.L.Debugf("RunWithIOWeightValue: completed with weight=%d", weight)
	return res.value, res.err
}

// RunWithIOWeight runs the given function in a dedicated OS thread
// with configured IO weight from environment variable via cgroup io.weight/io.bfq.weight.
// This function blocks until fn completes.
// The dedicated OS thread is terminated after fn returns.
func RunWithIOWeight[T any](fn func() (T, error)) (T, error) {
	return RunWithIOWeightValue(getConfiguredIOWeight(), fn)
}

// LocalRunWithIOWeightValue locks the current goroutine to its OS thread,
// creates a child cgroup with the specified IO weight, moves the thread into it,
// runs the function, moves the thread back, and destroys the child cgroup.
// If weight is 0, the function runs without IO weight adjustment.
// This ensures the IO weight setting only affects the current goroutine
// and doesn't leak to other goroutines that might later use the same thread.
//
// Use this when:
// - You're already in a goroutine and want to run IO operations with specified weight
// - You want to ensure other goroutines on the same thread aren't affected
//
// This function blocks until fn completes.
//
// For functions that return only an error, use: _, err := LocalRunWithIOWeightValue(...)
func LocalRunWithIOWeightValue[T any](weight uint16, fn func() (T, error)) (T, error) {
	if weight == 0 {
		return fn()
	}

	log.L.Debugf("LocalRunWithIOWeightValue: starting with weight=%d", weight)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Create child cgroup with specified IO weight
	cg, err := createIOWeightCgroup(weight)
	if err != nil {
		log.L.WithError(err).Debug("Failed to create IO weight cgroup, running without IO weight control")
		return fn()
	}
	defer func() {
		// Leave the child cgroup and destroy it
		if err := cg.leave(); err != nil {
			log.L.WithError(err).Debug("Failed to leave child cgroup")
		}
		cg.destroy()
		log.L.Debugf("LocalRunWithIOWeightValue: completed with weight=%d", weight)
	}()

	// Enter the child cgroup
	if err := cg.enter(); err != nil {
		log.L.WithError(err).Debug("Failed to enter child cgroup, running without IO weight control")
		return fn()
	}

	return fn()
}

// LocalRunWithIOWeight locks the current goroutine to its OS thread,
// sets configured IO weight from environment variable via cgroup io.weight/io.bfq.weight,
// runs the function, restores the original IO weight, and then unlocks the thread.
// This ensures the IO weight setting only affects the current goroutine
// and doesn't leak to other goroutines that might later use the same thread.
//
// Use this when:
// - You're already in a goroutine and want to run IO operations with configured weight
// - You want to ensure other goroutines on the same thread aren't affected
//
// This function blocks until fn completes.
//
// For functions that return only an error, use: _, err := LocalRunWithIOWeight(...)
func LocalRunWithIOWeight[T any](fn func() (T, error)) (T, error) {
	return LocalRunWithIOWeightValue(getConfiguredIOWeight(), fn)
}
