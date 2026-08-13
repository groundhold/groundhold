package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// receiptPendingParitySHA256 pins the shared receipt-pending parity fixture. The
// SAME file and constant live in the console
// (proviso-console/internal/server/receiptpending_parity_test.go). The console's
// in-flight fold decides which receipt statuses leave an operation UNSETTLED
// (a resource may exist and be billed) and mirrored `pending`/`unknown` by hand
// — a hardcoded subset of this package's closed status set, with no default arm.
// If a new leaves-pending status were added here, the console would silently not
// count it and under-report in-flight operations (a good-news drift, the D641/
// D328 class). This closes it: both repos execute one fixture, and the fixture is
// pinned to the LIVE ReceiptStatuses() below — a new status fails this test until
// the fixture (and then the console) learns it.
//
// The constant is the cross-repo sync anchor. (D1023.)
const receiptPendingParitySHA256 = "9f5f202a20d611676d843f46c82237335fba8c06575f59e1ca785e58b1007f0b"

type receiptPendingCase struct {
	Status        string `json:"status"`
	LeavesPending bool   `json:"leavesPending"`
}

// TestReceiptPendingParityIsTheContract proves the fixture against the REAL
// ReceiptLeavesIntentPending, and pins the fixture to cover EXACTLY the closed
// ReceiptStatuses() set — the authority the console mirrors.
func TestReceiptPendingParityIsTheContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "receiptpending_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != receiptPendingParitySHA256 {
		t.Fatalf("receipt-pending parity fixture sha256 = %s, pinned = %s — regenerate "+
			"the constant here AND in the console", got, receiptPendingParitySHA256)
	}
	var doc struct {
		Statuses []receiptPendingCase `json:"statuses"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parity fixture is not valid JSON: %v", err)
	}

	// 1. Every fixture entry agrees with the real classifier.
	inFixture := map[string]bool{}
	for _, c := range doc.Statuses {
		inFixture[c.Status] = true
		if c.LeavesPending != ReceiptLeavesIntentPending(c.Status) {
			t.Errorf("status %q: fixture leavesPending=%v, runtime ReceiptLeavesIntentPending=%v",
				c.Status, c.LeavesPending, ReceiptLeavesIntentPending(c.Status))
		}
	}
	// 2. The fixture covers EXACTLY the closed set — no runtime status omitted
	//    (which the console would then silently fail to classify), none stale.
	inRuntime := map[string]bool{}
	for _, st := range ReceiptStatuses() {
		inRuntime[st] = true
		if !inFixture[st] {
			t.Errorf("ReceiptStatuses() includes %q but the fixture omits it — the console "+
				"would not know how to classify a status the ledger emits", st)
		}
	}
	for st := range inFixture {
		if !inRuntime[st] {
			t.Errorf("the fixture lists %q which ReceiptStatuses() no longer contains — stale", st)
		}
	}
}

// TestReceiptStatusSliceAndValidatorAgree closes a published-registries-drift IN
// THIS FILE: the closed receipt-status set is enumerated twice — ReceiptStatuses()
// (the slice the parity fixtures and TestBothFoldsAgreeOnWhichReceiptsStayPending
// iterate) and the receiptStatuses map (the PRODUCTION validator: recordReceipt
// rejects any status with `!receiptStatuses[status]`). Nothing tied them. A status
// added to the validator but not the slice would flow through production while the
// D1023 fixture — pinned to the SLICE — stayed blind to it, hollowing that gate;
// the reverse would reject a status the fixtures treat as valid. They must have
// identical members.
func TestReceiptStatusSliceAndValidatorAgree(t *testing.T) {
	inSlice := map[string]bool{}
	for _, s := range ReceiptStatuses() {
		inSlice[s] = true
		if !receiptStatuses[s] {
			t.Errorf("ReceiptStatuses() lists %q but the receiptStatuses validator omits it — "+
				"recordReceipt would REJECT a status the parity fixtures treat as valid", s)
		}
	}
	for s := range receiptStatuses {
		if !inSlice[s] {
			t.Errorf("the receiptStatuses validator accepts %q but ReceiptStatuses() omits it — "+
				"production accepts a status the D1023 fixture (pinned to the slice) never checks", s)
		}
	}
}
