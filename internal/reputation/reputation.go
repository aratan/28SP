package reputation

import (
	"sync"
	"time"
)

// ReputationRecord represents a peer's reputation metrics
type ReputationRecord struct {
	PeerID          string
	Score           float64
	MessageCount    int
	ValidMessages   int
	InvalidMessages int
	LastActivity    time.Time
	Reports         []Report
}

// Report represents a reputation report about a peer
type Report struct {
	ReporterID string
	Score      float64
	Reason     string
	Timestamp  time.Time
}

// ReputationSystem manages peer reputations
type ReputationSystem struct {
	records map[string]*ReputationRecord
	mutex   sync.RWMutex
}

// NewReputationSystem creates a new reputation system
func NewReputationSystem() *ReputationSystem {
	return &ReputationSystem{
		records: make(map[string]*ReputationRecord),
	}
}

// GetReputation gets a peer's reputation score
func (rs *ReputationSystem) GetReputation(peerID string) float64 {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()
	
	record, exists := rs.records[peerID]
	if !exists {
		return 0.0 // Default score for unknown peers
	}
	
	return record.Score
}

// ReportPeer reports a peer's behavior
func (rs *ReputationSystem) ReportPeer(peerID, reporterID, reason string, score float64) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	
	record, exists := rs.records[peerID]
	if !exists {
		record = &ReputationRecord{
			PeerID:       peerID,
			Score:        0.0,
			MessageCount: 0,
			Reports:      make([]Report, 0),
		}
		rs.records[peerID] = record
	}
	
	// Add the report
	report := Report{
		ReporterID: reporterID,
		Score:      score,
		Reason:     reason,
		Timestamp:  time.Now(),
	}
	record.Reports = append(record.Reports, report)
	
	// Update the score (simple average for now)
	record.Score = (record.Score*float64(len(record.Reports)-1) + score) / float64(len(record.Reports))
	record.LastActivity = time.Now()
}

// RecordMessage records a message from a peer
func (rs *ReputationSystem) RecordMessage(peerID string, valid bool) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	
	record, exists := rs.records[peerID]
	if !exists {
		record = &ReputationRecord{
			PeerID:       peerID,
			Score:        0.0,
			MessageCount: 0,
			Reports:      make([]Report, 0),
		}
		rs.records[peerID] = record
	}
	
	// Update message counts
	record.MessageCount++
	if valid {
		record.ValidMessages++
	} else {
		record.InvalidMessages++
	}
	
	// Update score based on message validity
	if record.MessageCount > 0 {
		validityScore := float64(record.ValidMessages) / float64(record.MessageCount)
		// Weight the validity score (0.7) and existing score (0.3)
		record.Score = 0.3*record.Score + 0.7*validityScore
	}
	
	record.LastActivity = time.Now()
}

// IsTrustedPeer checks if a peer is trusted based on their reputation score
func (rs *ReputationSystem) IsTrustedPeer(peerID string, threshold float64) bool {
	score := rs.GetReputation(peerID)
	return score >= threshold
}

// GetMaliciousPeers returns a list of peers below the trust threshold
func (rs *ReputationSystem) GetMaliciousPeers(threshold float64) []string {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()
	
	var maliciousPeers []string
	for peerID, record := range rs.records {
		if record.Score < threshold {
			maliciousPeers = append(maliciousPeers, peerID)
		}
	}
	
	return maliciousPeers
}

// CleanupInactivePeers removes records of peers that haven't been active for a while
func (rs *ReputationSystem) CleanupInactivePeers(maxAge time.Duration) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	
	now := time.Now()
	for peerID, record := range rs.records {
		if now.Sub(record.LastActivity) > maxAge {
			delete(rs.records, peerID)
		}
	}
}

// GetPeerReport returns detailed information about a peer's reputation
func (rs *ReputationSystem) GetPeerReport(peerID string) *ReputationRecord {
	rs.mutex.RLock()
	defer rs.mutex.RUnlock()
	
	record, exists := rs.records[peerID]
	if !exists {
		return nil
	}
	
	// Return a copy to prevent external modification
	copy := &ReputationRecord{
		PeerID:          record.PeerID,
		Score:           record.Score,
		MessageCount:    record.MessageCount,
		ValidMessages:   record.ValidMessages,
		InvalidMessages: record.InvalidMessages,
		LastActivity:    record.LastActivity,
		Reports:         make([]Report, len(record.Reports)),
	}
	
	for i, report := range record.Reports {
		copy.Reports[i] = Report{
			ReporterID: report.ReporterID,
			Score:      report.Score,
			Reason:     report.Reason,
			Timestamp:  report.Timestamp,
		}
	}
	
	return copy
}