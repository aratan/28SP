package reputation

import (
	"testing"
)

func TestReputationSystem(t *testing.T) {
	// Create a new reputation system
	rs := NewReputationSystem()

	if rs == nil {
		t.Fatal("Failed to create reputation system")
	}

	// Test getting reputation for unknown peer
	score := rs.GetReputation("unknown-peer")
	if score != 0.0 {
		t.Errorf("Expected 0.0 for unknown peer, got %f", score)
	}
}

func TestReportPeer(t *testing.T) {
	rs := NewReputationSystem()

	// Report a peer
	rs.ReportPeer("test-peer", "reporter-1", "good behavior", 1.0)

	// Check the reputation score
	score := rs.GetReputation("test-peer")
	if score != 1.0 {
		t.Errorf("Expected 1.0 for reported peer, got %f", score)
	}

	// Report the same peer with a different score
	rs.ReportPeer("test-peer", "reporter-2", "bad behavior", 0.0)

	// Check the updated reputation score (should be average)
	score = rs.GetReputation("test-peer")
	expected := 0.5 // Average of 1.0 and 0.0
	if score != expected {
		t.Errorf("Expected %f for reported peer, got %f", expected, score)
	}
}

func TestRecordMessage(t *testing.T) {
	rs := NewReputationSystem()

	// Record a valid message
	rs.RecordMessage("test-peer", true)

	// Check the reputation score
	score := rs.GetReputation("test-peer")
	if score <= 0.0 {
		t.Errorf("Expected positive score for valid message, got %f", score)
	}

	// Record an invalid message
	rs.RecordMessage("test-peer", false)

	// Check the updated reputation score
	score = rs.GetReputation("test-peer")
	if score >= 1.0 {
		t.Errorf("Expected lower score after invalid message, got %f", score)
	}
}

func TestIsTrustedPeer(t *testing.T) {
	rs := NewReputationSystem()

	// Report a peer with a good score
	rs.ReportPeer("trusted-peer", "reporter-1", "good behavior", 1.0)

	// Check if the peer is trusted
	if !rs.IsTrustedPeer("trusted-peer", 0.5) {
		t.Error("Expected trusted-peer to be trusted")
	}

	// Report another peer with a bad score
	rs.ReportPeer("untrusted-peer", "reporter-1", "bad behavior", 0.0)

	// Check if the peer is untrusted
	if rs.IsTrustedPeer("untrusted-peer", 0.5) {
		t.Error("Expected untrusted-peer to be untrusted")
	}
}

func TestGetMaliciousPeers(t *testing.T) {
	rs := NewReputationSystem()

	// Report some peers
	rs.ReportPeer("good-peer", "reporter-1", "good behavior", 1.0)
	rs.ReportPeer("bad-peer", "reporter-1", "bad behavior", 0.0)

	// Get malicious peers
	malicious := rs.GetMaliciousPeers(0.5)

	// Should only contain the bad peer
	if len(malicious) != 1 {
		t.Errorf("Expected 1 malicious peer, got %d", len(malicious))
	}

	if len(malicious) > 0 && malicious[0] != "bad-peer" {
		t.Errorf("Expected bad-peer to be malicious, got %s", malicious[0])
	}
}

func TestGetPeerReport(t *testing.T) {
	rs := NewReputationSystem()

	// Report a peer
	rs.ReportPeer("test-peer", "reporter-1", "good behavior", 1.0)

	// Get the peer report
	report := rs.GetPeerReport("test-peer")

	if report == nil {
		t.Fatal("Expected peer report, got nil")
	}

	if report.PeerID != "test-peer" {
		t.Errorf("Expected peer ID test-peer, got %s", report.PeerID)
	}

	if len(report.Reports) != 1 {
		t.Errorf("Expected 1 report, got %d", len(report.Reports))
	}
}