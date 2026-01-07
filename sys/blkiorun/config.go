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

// Config holds configuration for block IO operations
type Config struct {
	Weight uint16 // IO weight (10-1000, BFQ range)
}

const (
	// BFQWeightMin is the minimum BFQ IO weight
	BFQWeightMin uint16 = 10
	// BFQWeightMax is the maximum BFQ IO weight
	BFQWeightMax uint16 = 1000
	// BFQWeightDefault is the default BFQ IO weight
	BFQWeightDefault uint16 = 100

	// IOWeightMin is the minimum io.weight value
	IOWeightMin uint64 = 1
	// IOWeightMax is the maximum io.weight value
	IOWeightMax uint64 = 10000

	// Conversion factors for BFQ <-> io.weight
	// io.weight = 1 + (bfq - 10) * 9999 / 990
	// bfq = 10 + (io.weight - 1) * 990 / 9999
	conversionNumerator   = 9999
	conversionDenominator = 990
)

// ConvertBFQToIOWeight converts BFQ weight (10-1000) to io.weight (1-10000).
func ConvertBFQToIOWeight(bfqWeight uint16) uint64 {
	if bfqWeight == 0 {
		return 0
	}
	return uint64(IOWeightMin) + (uint64(bfqWeight)-uint64(BFQWeightMin))*conversionNumerator/conversionDenominator
}

// ConvertIOWeightToBFQ converts io.weight (1-10000) back to BFQ weight (10-1000).
func ConvertIOWeightToBFQ(ioWeight uint64) uint16 {
	if ioWeight == 0 {
		return 0
	}
	if ioWeight <= IOWeightMin {
		return BFQWeightMin
	}
	if ioWeight >= IOWeightMax {
		return BFQWeightMax
	}
	return BFQWeightMin + uint16((ioWeight-IOWeightMin)*conversionDenominator/conversionNumerator)
}
