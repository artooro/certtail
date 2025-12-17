package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
)

const (
	logListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
)

// Define local structs to match the JSON structure of log_list.json
type LogList struct {
	Operators []Operator `json:"operators"`
}

type Operator struct {
	Name  string    `json:"name"`
	Email []string  `json:"email"` // Changed from string to []string
	Logs  []LogInfo `json:"logs"`
}

type LogInfo struct {
	URL         string `json:"url"`
	Description string `json:"description"`
}

func main() {
	// Get the list of logs
	logList, err := getLogList(logListURL)
	if err != nil {
		log.Fatalf("Failed to get log list: %v", err)
	}

	var selectedLogInfo LogInfo
	foundLog := false

	// Iterate through operators and their logs to find the first available log
	for _, operator := range logList.Operators {
		if len(operator.Logs) > 0 {
			selectedLogInfo = operator.Logs[0]
			foundLog = true
			break
		}
	}

	if !foundLog {
		log.Fatal("No logs found in the log list.")
	}

	// Create a new CT client
	logClient, err := client.New(selectedLogInfo.URL, http.DefaultClient, jsonclient.Options{})
	if err != nil {
		log.Fatalf("Failed to create CT client: %v", err)
	}

	// Get the initial STH (Signed Tree Head)
	sth, err := logClient.GetSTH(context.Background())
	if err != nil {
		log.Fatalf("Failed to get initial STH: %v", err)
	}

	log.Printf("Monitoring log: %s", selectedLogInfo.Description)
	log.Printf("Initial tree size: %d", sth.TreeSize)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var nextIndex int64 = int64(sth.TreeSize)

	for {
		select {
		case <-ticker.C:
			// Fetch the current STH to get the most up-to-date tree size.
			currentSTH, err := logClient.GetSTH(context.Background())
			if err != nil {
				log.Printf("Failed to get current STH: %v", err)
				continue
			}

			if currentSTH.TreeSize <= uint64(nextIndex) { // Cast nextIndex to uint64
				// No new entries yet, continue waiting.
				continue
			}

			// Fetch entries from nextIndex up to the current tree size.
			entries, err := logClient.GetEntries(context.Background(), nextIndex, int64(currentSTH.TreeSize))
			if err != nil {
				log.Printf("Failed to get entries: %v", err)
				continue
			}

			            for _, entry := range entries {
			                nextIndex++
			                if entry.X509Cert != nil { // Outer check for X509Cert
			                    // Parse certificate only once if it's an X509Cert entry
			                    cert, err := x509.ParseCertificate(entry.X509Cert.Raw)
			                    if err != nil {
			                        log.Printf("Failed to parse X509 certificate: %v", err)
			                        continue
			                    }
			
			                    // The timestamp is actually in the MerkleTreeLeaf, which is part of the LogEntry.
			                    // For X509Cert entries, the timestamp is typically the notBefore date of the certificate
			                    // or the timestamp from the SignedCertificateTransparency.
			                    // However, the original request was to get the timestamp from the log entry itself.
			                    // Assuming entry.Leaf.TimestampedEntry is still the source for the CT log timestamp.
			                    if entry.Leaf.TimestampedEntry != nil { // Inner check for timestamp
			                        timestamp := time.Unix(0, int64(entry.Leaf.TimestampedEntry.Timestamp)*int64(time.Millisecond))
			                        fmt.Printf("Timestamp: %s, Issuer: %s, Subject: %s\n",
			                            timestamp.Format(time.RFC3339),
			                            cert.Issuer.String(),
			                            cert.Subject.String(),
			                        )
			                    } else {
			                        log.Printf("Skipping X509Cert entry %d: TimestampedEntry is nil", nextIndex-1)
			                    }
			                } else if entry.Precert != nil { // Handle pre-certificates
			                    log.Printf("Skipping precertificate entry %d", nextIndex-1)
			                } else { // Handle other unknown entry types
			                    log.Printf("Skipping unknown entry type %d", nextIndex-1)
			                }
			            }
			        } // Closes the select statement
			    } // Closes the for loop
			} // Closes the main function
// getLogList fetches and parses the log list from the given URL.
func getLogList(url string) (*LogList, error) { // Use local LogList struct
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch log list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch log list: status %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read log list body: %w", err)
	}

	var logList LogList // Use local LogList struct
	if err := json.Unmarshal(body, &logList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal log list: %w", err)
	}

	return &logList, nil
}
