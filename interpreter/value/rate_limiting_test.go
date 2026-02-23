package value

import (
	"testing"
	"time"

	"github.com/ysugimoto/falco/ast"
)

func TestCalculateBucket(t *testing.T) {
	// 2023-03-15 13:20:08 UTC
	fixedTime := int64(1678886408)

	entries := []rateEntry{
		{Count: 1, Timestamp: fixedTime - 5000},  // 1678886403
		{Count: 1, Timestamp: fixedTime - 15000}, // 1678886393
		{Count: 1, Timestamp: fixedTime - 25000}, // 1678886383
	}

	// 10s window: from 1678886390, to 1678886400. window is [1678886390, 1678886410)
	// entries are 1678886403, 1678886393. bucket should be 2
	if val := calculateBucketWithTime(fixedTime, entries, 10*time.Second); val != 1 {
		t.Errorf("bucket(10s) expected 2, got %d", val)
	}

	// 20s window: from 1678886380, to 1678886400. window is [1678886380, 1678886410)
	// entries are 1678886403, 1678886393, 1678886383. bucket should be 3
	if val := calculateBucketWithTime(fixedTime, entries, 20*time.Second); val != 2 {
		t.Errorf("bucket(20s) expected 3, got %d", val)
	}

	// 30s window: from 1678886370, to 1678886400. window is [1678886370, 1678886410)
	// entries are 1678886403, 1678886393, 1678886383. bucket should be 3
	if val := calculateBucketWithTime(fixedTime, entries, 30*time.Second); val != 3 {
		t.Errorf("bucket(30s) expected 3, got %d", val)
	}
}

func TestCalculateRate(t *testing.T) {
	// 2023-03-15 13:20:08 UTC
	fixedTime := int64(1678886408)

	entries := []rateEntry{
		{Count: 1, Timestamp: fixedTime - 5},  // 1678886403
		{Count: 1, Timestamp: fixedTime - 15}, // 1678886393
		{Count: 1, Timestamp: fixedTime - 25}, // 1678886383
	}

	// 10s window: bucket is 1, rate is floor(1 / 10) = 0
	if val := calculateRateWithTime(fixedTime, entries, 10*time.Second); val != 0 {
		t.Errorf("rate(10s) expected 0, got %f", val)
	}

	// 20s window: bucket is 2, rate is floor(2 / 20) = 0
	if val := calculateRateWithTime(fixedTime, entries, 20*time.Second); val != 0 {
		t.Errorf("rate(20s) expected 0, got %f", val)
	}

	// 60s window: bucket is 3, rate is floor(3 / 60) = 0
	if val := calculateRateWithTime(fixedTime, entries, 60*time.Second); val != 0 {
		t.Errorf("rate(60s) expected 0, got %f", val)
	}
}

func TestCalculateRateReplicate(t *testing.T) {
	fixedTime := int64(1678886408)
	entries := []rateEntry{
		{Count: 1, Timestamp: fixedTime - 5},  // 1678886403
		{Count: 1, Timestamp: fixedTime - 15}, // 1678886393
		{Count: 1, Timestamp: fixedTime - 25}, // 1678886383
	}
	if val := calculateRateWithTime(fixedTime, entries, 60*time.Second); val != 0 {
		t.Errorf("rate(60s) expected 0, got %f", val)
	}
}

func TestPenaltybox(t *testing.T) {
	pb := NewPenaltybox(&ast.PenaltyboxDeclaration{
		Name: &ast.Ident{Value: "testpenaltybox"},
	})
	client := "127.0.0.1"
	anotherClient := "192.168.0.1"

	// Test Add and Has
	pb.Add(client, 1*time.Second)
	if !pb.Has(client) {
		t.Errorf("Expected client to be in penaltybox, but wasn't")
	}
	if pb.Has(anotherClient) {
		t.Errorf("Expected anotherClient not to be in penaltybox, but was")
	}

	// Test expiration
	time.Sleep(1 * time.Second)
	if pb.Has(client) {
		t.Errorf("Expected client to be expired from penaltybox, but wasn't")
	}

	// Test invalid entry type
	pb.Clients.Store("invalid", "not a time object")
	if pb.Has("invalid") {
		t.Errorf("Expected invalid entry to be handled and return false, but returned true")
	}
	if _, ok := pb.Clients.Load("invalid"); ok {
		t.Errorf("Expected invalid entry to be deleted, but it still exists")
	}
}

// Ratecounter implementation is hard to test with unit because it depends on time.Now().
// So we may need to write some integration tests with interpreter.
// But we add simple test case for a while.
func TestRatecounter(t *testing.T) {
	rc := NewRatecounter(&ast.RatecounterDeclaration{
		Name: &ast.Ident{Value: "testratecounter"},
	})
	client := "127.0.0.1"

	// Before calling any function, bucket and rate should be 0
	if bucket := rc.Bucket(client, 10*time.Second); bucket != 0 {
		t.Errorf("Expected initial bucket to be 0, got %d", bucket)
	}
	if rate := rc.Rate(client, 10*time.Second); rate != 0 {
		t.Errorf("Expected initial rate to be 0, got %f", rate)
	}

	// After increment, IsAccessible should be true
	rc.Increment(client, 1)
	if rc.LastIncremented == nil {
		t.Errorf("Expected IsAccessible to be true after Increment, but was false")
	}

	// After increment, bucket and rate should be accessible
	if bucket := rc.Bucket(client, 10*time.Second); bucket == 0 {
		t.Errorf("Expected bucket to be non-zero after Increment, but was 0")
	}
	// Rate is calculated on completed 10-second periods, so the rate will be 0 just after increment.
	if rate := rc.Rate(client, 10*time.Second); rate != 0 {
		t.Errorf("Expected rate to be 0 right after increment, but was %f", rate)
	}
}
