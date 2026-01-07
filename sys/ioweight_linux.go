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
)

// getConfiguredIOWeight returns the configured IO weight from environment variable.
// Returns 0 if not configured or invalid.
func getConfiguredIOWeight() uint16 {
	configuredIOWeightOnce.Do(func() {
		val := os.Getenv(IOWeightEnvKey)
		if val == "" {
			return
		}

		weight, err := strconv.ParseUint(val, 10, 16)
		if err != nil {
			return
		}

		// Validate range
		if weight < bfqWeightMin || weight > bfqWeightMax {
			return
		}

		configuredIOWeight = uint16(weight)
	})
	return configuredIOWeight
}

// isCgroupV2Enabled checks if cgroups v2 is enabled on the system.
func isCgroupV2Enabled() bool {
	cgroupV2EnabledOnce.Do(func() {
		// Check if cgroup2 filesystem is mounted at /sys/fs/cgroup
		if stat, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil && !stat.IsDir() {
			cgroupV2Enabled = true
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
			return
		}

		bfqPath := filepath.Join(cgroupPath, "io.bfq.weight")
		if _, err := os.Stat(bfqPath); err == nil {
			bfqSupported = true
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
			return nil
		}
	}

	// Fallback to io.weight with conversion
	ioWeight := convertBFQToIOWeight(weight)
	ioWeightPath := filepath.Join(cgroupPath, "io.weight")
	return os.WriteFile(ioWeightPath, []byte(strconv.FormatUint(ioWeight, 10)), 0644)
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

// setIOWeightCgroup sets the current process's cgroup to use configured IO weight.
// Returns the original weight value, or 0 if operation failed.
func setIOWeightCgroup() uint16 {
	weight := getConfiguredIOWeight()
	if weight == 0 {
		return 0
	}

	origWeight, err := readIOWeight()
	if err != nil {
		return 0
	}

	// Set to configured weight
	_ = writeIOWeight(weight)
	return origWeight
}

// restoreIOWeightCgroup restores the cgroup IO weight to the specified value.
func restoreIOWeightCgroup(weight uint16) {
	if weight == 0 {
		return
	}
	_ = writeIOWeight(weight)
}

// RunWithIOWeight runs the given function in a dedicated OS thread
// with configured IO weight via cgroup io.weight/io.bfq.weight.
// This function blocks until fn completes.
// The dedicated OS thread is terminated after fn returns.
func RunWithIOWeight[T any](fn func() (T, error)) (T, error) {
	if getConfiguredIOWeight() == 0 {
		return fn()
	}

	type result struct {
		value T
		err   error
	}

	resCh := make(chan result, 1)

	go func() {
		// we discard this OS thread after use
		runtime.LockOSThread()

		// Set configured IO weight via cgroups
		_ = setIOWeightCgroup()

		v, err := fn()
		resCh <- result{value: v, err: err}
	}()

	res := <-resCh
	return res.value, res.err
}

// LocalRunWithIOWeight locks the current goroutine to its OS thread,
// sets configured IO weight via cgroup io.weight/io.bfq.weight, runs the function,
// restores the original IO weight, and then unlocks the thread.
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
	if getConfiguredIOWeight() == 0 {
		return fn()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Set configured IO weight via cgroups and restore on exit
	origWeight := setIOWeightCgroup()
	defer restoreIOWeightCgroup(origWeight)

	return fn()
}
