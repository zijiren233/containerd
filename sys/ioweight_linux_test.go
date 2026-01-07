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
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertBFQToIOWeight(t *testing.T) {
	tests := []struct {
		name      string
		bfqWeight uint16
		expected  uint64
	}{
		{
			name:      "zero weight",
			bfqWeight: 0,
			expected:  0,
		},
		{
			name:      "minimum BFQ weight",
			bfqWeight: 10,
			expected:  1,
		},
		{
			name:      "normal BFQ weight",
			bfqWeight: 100,
			expected:  910,
		},
		{
			name:      "maximum BFQ weight",
			bfqWeight: 1000,
			expected:  10000,
		},
		{
			name:      "mid-range BFQ weight",
			bfqWeight: 500,
			expected:  4950,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertBFQToIOWeight(tt.bfqWeight)
			assert.Equal(t, tt.expected, result, "BFQ weight %d should convert to io.weight %d", tt.bfqWeight, tt.expected)
		})
	}
}

func TestConvertIOWeightToBFQ(t *testing.T) {
	tests := []struct {
		name     string
		ioWeight uint64
		expected uint16
	}{
		{
			name:     "zero weight",
			ioWeight: 0,
			expected: 0,
		},
		{
			name:     "minimum io.weight",
			ioWeight: 1,
			expected: 10,
		},
		{
			name:     "below minimum",
			ioWeight: 0,
			expected: 0,
		},
		{
			name:     "mid-range io.weight",
			ioWeight: 5000,
			expected: 504,
		},
		{
			name:     "maximum io.weight",
			ioWeight: 10000,
			expected: 1000,
		},
		{
			name:     "above maximum",
			ioWeight: 15000,
			expected: 1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertIOWeightToBFQ(tt.ioWeight)
			assert.Equal(t, tt.expected, result, "io.weight %d should convert to BFQ weight %d", tt.ioWeight, tt.expected)
		})
	}
}

func TestConversionRoundTrip(t *testing.T) {
	// Test that converting from BFQ to IO and back gives approximately the same value
	tests := []uint16{10, 50, 100, 200, 500, 1000}

	for _, bfqWeight := range tests {
		ioWeight := convertBFQToIOWeight(bfqWeight)
		converted := convertIOWeightToBFQ(ioWeight)

		// Allow for small rounding errors in conversion
		diff := int(bfqWeight) - int(converted)
		if diff < 0 {
			diff = -diff
		}
		assert.LessOrEqual(t, diff, 1, "Round-trip conversion for BFQ weight %d should be within 1", bfqWeight)
	}
}

func TestGetCurrentCgroupPathParsing(t *testing.T) {
	path, err := getCurrentCgroupPath()
	if err != nil {
		t.Skipf("Skipping test: cgroups v2 not available: %v", err)
	}

	// Verify the path structure
	assert.True(t, strings.HasPrefix(path, "/sys/fs/cgroup"), "Path should start with /sys/fs/cgroup")

	// Try to stat the path to ensure it exists
	info, err := os.Stat(path)
	if err == nil {
		assert.True(t, info.IsDir(), "Cgroup path should be a directory")
	}
}

func TestReadIOWeight(t *testing.T) {
	if !isCgroupV2Enabled() {
		t.Skip("Test requires cgroups v2")
	}

	weight, err := readIOWeight()
	if err != nil {
		// readIOWeight may fail if we don't have proper permissions
		// or if the files don't exist, which is acceptable
		t.Logf("readIOWeight failed (this may be expected): %v", err)
		return
	}

	// If successful, weight should be in valid range
	assert.GreaterOrEqual(t, weight, uint16(10), "Weight should be at least minimum")
	assert.LessOrEqual(t, weight, uint16(1000), "Weight should be at most maximum")
}

// TestIOWeightSetAndRestore tests the complete flow of:
// 1. Reading current IO weight
// 2. Setting a new IO weight
// 3. Verifying the new weight is set
// 4. Restoring the original weight
// 5. Verifying the original weight is restored
func TestIOWeightSetAndRestore(t *testing.T) {
	if !isCgroupV2Enabled() {
		t.Skip("Test requires cgroups v2")
	}

	// Read the original IO weight
	originalWeight, err := readIOWeight()
	if err != nil {
		t.Skipf("Cannot read IO weight (may need permissions or BFQ scheduler): %v", err)
	}

	t.Logf("Original IO weight: %d", originalWeight)

	// Try to set a different weight
	testWeight := uint16(200)
	if originalWeight == testWeight {
		testWeight = 300 // Use a different value if original is 200
	}

	t.Logf("Attempting to set IO weight to: %d", testWeight)
	err = writeIOWeight(testWeight)
	if err != nil {
		t.Skipf("Cannot write IO weight (may need permissions): %v", err)
	}

	// Verify the weight was set
	currentWeight, err := readIOWeight()
	if err != nil {
		t.Fatalf("Failed to read IO weight after setting: %v", err)
	}

	t.Logf("Current IO weight after setting: %d", currentWeight)
	assert.Equal(t, testWeight, currentWeight, "IO weight should be set to the new value")

	// Restore the original weight
	t.Logf("Restoring original IO weight: %d", originalWeight)
	err = writeIOWeight(originalWeight)
	if err != nil {
		t.Fatalf("Failed to restore original IO weight: %v", err)
	}

	// Verify the weight was restored
	restoredWeight, err := readIOWeight()
	if err != nil {
		t.Fatalf("Failed to read IO weight after restoring: %v", err)
	}

	t.Logf("IO weight after restoring: %d", restoredWeight)
	assert.Equal(t, originalWeight, restoredWeight, "IO weight should be restored to the original value")
}

// TestSetAndRestoreIOWeightCgroupValue tests the setIOWeightCgroupValue and restoreIOWeightCgroup functions
func TestSetAndRestoreIOWeightCgroupValue(t *testing.T) {
	if !isCgroupV2Enabled() {
		t.Skip("Test requires cgroups v2")
	}

	// Read the original weight first
	originalWeight, err := readIOWeight()
	if err != nil {
		t.Skipf("Cannot read IO weight: %v", err)
	}

	t.Logf("Original IO weight: %d", originalWeight)

	// Test that we can write IO weight first
	testErr := writeIOWeight(150)
	if testErr != nil {
		t.Skipf("Cannot write IO weight (need permissions): %v", testErr)
	}

	// Call setIOWeightCgroupValue
	returnedWeight := setIOWeightCgroupValue(150)
	if returnedWeight == 0 {
		t.Skipf("setIOWeightCgroupValue failed (may need permissions or BFQ scheduler)")
	}

	t.Logf("setIOWeightCgroupValue returned: %d", returnedWeight)
	assert.Equal(t, originalWeight, returnedWeight, "setIOWeightCgroupValue should return the original weight")

	// Verify the weight was changed
	currentWeight, err := readIOWeight()
	if err != nil {
		t.Fatalf("Failed to read IO weight after setting: %v", err)
	}

	t.Logf("Current IO weight after setting: %d", currentWeight)
	assert.Equal(t, uint16(150), currentWeight, "IO weight should be set to 150")

	// Restore the original weight
	restoreIOWeightCgroup(returnedWeight)

	// Verify the weight was restored
	restoredWeight, err := readIOWeight()
	if err != nil {
		t.Fatalf("Failed to read IO weight after restoring: %v", err)
	}

	t.Logf("IO weight after restoring: %d", restoredWeight)
	assert.Equal(t, originalWeight, restoredWeight, "IO weight should be restored to the original value")
}

// TestRunWithIOWeightValueRealCgroup tests RunWithIOWeightValue with actual cgroup operations
func TestRunWithIOWeightValueRealCgroup(t *testing.T) {
	if !isCgroupV2Enabled() {
		t.Skip("Test requires cgroups v2")
	}

	// Get original weight
	originalWeight, err := readIOWeight()
	if err != nil {
		t.Skipf("Cannot read IO weight: %v", err)
	}

	t.Logf("Original IO weight before test: %d", originalWeight)

	// Test that we can write IO weight first
	testErr := writeIOWeight(250)
	if testErr != nil {
		t.Skipf("Cannot write IO weight (need permissions): %v", testErr)
	}
	// Restore it immediately
	_ = writeIOWeight(originalWeight)

	// Run a function with IO weight
	var weightInFunction uint16
	result, err := RunWithIOWeightValue(250, func() (string, error) {
		// Try to read the weight inside the function
		// Note: This may not show the changed weight because we're in a different goroutine/thread
		w, readErr := readIOWeight()
		if readErr == nil {
			weightInFunction = w
		}
		return "test-result", nil
	})

	assert.NoError(t, err)
	assert.Equal(t, "test-result", result)

	// The weight after the function completes should be back to original
	// (or at least the function should have executed)
	finalWeight, err := readIOWeight()
	if err != nil {
		t.Logf("Cannot read final weight: %v", err)
	} else {
		t.Logf("Final IO weight after test: %d", finalWeight)
		t.Logf("Weight observed in function: %d", weightInFunction)
	}
}

// TestLocalRunWithIOWeightValueRealCgroup tests LocalRunWithIOWeightValue with actual cgroup operations
func TestLocalRunWithIOWeightValueRealCgroup(t *testing.T) {
	if !isCgroupV2Enabled() {
		t.Skip("Test requires cgroups v2")
	}

	// Get original weight
	originalWeight, err := readIOWeight()
	if err != nil {
		t.Skipf("Cannot read IO weight: %v", err)
	}

	t.Logf("Original IO weight before test: %d", originalWeight)

	// Test that we can write IO weight first
	testErr := writeIOWeight(350)
	if testErr != nil {
		t.Skipf("Cannot write IO weight (need permissions): %v", testErr)
	}
	// Restore it immediately
	_ = writeIOWeight(originalWeight)

	// Run a function with IO weight
	var weightInFunction uint16
	result, err := LocalRunWithIOWeightValue(350, func() (string, error) {
		// Read the weight inside the function - should be the configured weight
		w, readErr := readIOWeight()
		if readErr == nil {
			weightInFunction = w
		}
		return "test-result", nil
	})

	assert.NoError(t, err)
	assert.Equal(t, "test-result", result)

	t.Logf("Weight observed in function: %d (expected 350)", weightInFunction)
	if weightInFunction != 0 {
		assert.Equal(t, uint16(350), weightInFunction, "Weight inside function should be 350")
	}

	// The weight after the function completes should be restored
	finalWeight, err := readIOWeight()
	if err != nil {
		t.Logf("Cannot read final weight: %v", err)
	} else {
		t.Logf("Final IO weight after test: %d (should be %d)", finalWeight, originalWeight)
		assert.Equal(t, originalWeight, finalWeight, "Weight should be restored after LocalRunWithIOWeightValue")
	}
}
