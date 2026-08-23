package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D1251. The verb/reference PARITY is gated in internal/provider (D1125) and stays there
// — one claim, one gate. What lives here is the half that gate cannot ask: whether the
// one-line description a verb ships with survives contact with running the verb.

// And the one-line description a verb ships with has to survive contact with running it.
// `k8s-skeleton` called itself "offline mapping scaffolding" — which meant "writes
// nothing" to its author and "needs no cluster" to a reader, and the verb refuses at a
// desk with no kubeconfig because the schema comes from a live API server.
func TestTheSkeletonVerbDoesNotCallItselfOffline(t *testing.T) {
	root := repoRootFromCmd(t)
	src, err := os.ReadFile(filepath.Join(root, "go", "cmd", "groundhold", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	i := strings.Index(body, "groundhold k8s-skeleton <group>")
	if i < 0 {
		t.Fatal("the k8s-skeleton usage line is gone — move this gate with it")
	}
	block := body[i:min(i+400, len(body))]
	if strings.Contains(block, "offline") {
		t.Error("k8s-skeleton describes itself as offline and it requires a reachable API " +
			"server — the word reads as \"needs no cluster\" to everyone who is not the " +
			"author, and the verb refuses without one")
	}
	if !strings.Contains(block, "READS a live cluster") {
		t.Error("the usage line must say it reads a live cluster — a scaffolding tool that " +
			"silently needs one is chosen for the wrong moment")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
