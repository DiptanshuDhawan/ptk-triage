package rules

import (
	"fmt"
	"testing"

	"ptk/internal/model"
)

// buildLargeFFUFSet synthesizes a realistic large ffuf-style result set: a lot
// of noise-floor 200s plus a sprinkling of varied statuses, approximating a
// real wordlist run at scale.
func buildLargeFFUFSet(n int) []model.Item {
	items := make([]model.Item, 0, n)
	for i := 0; i < n; i++ {
		switch i % 37 {
		case 0:
			items = append(items, model.Item{Kind: model.KindPath, URL: fmt.Sprintf("http://t/admin%d", i), Path: "admin", Status: 403, Length: 512})
		case 1:
			items = append(items, model.Item{Kind: model.KindPath, URL: fmt.Sprintf("http://t/x%d.bak", i), Path: "x.bak", Status: 200, Length: 900})
		default:
			items = append(items, model.Item{Kind: model.KindPath, URL: fmt.Sprintf("http://t/w%d", i), Path: fmt.Sprintf("w%d", i), Status: 200, Length: 4096})
		}
	}
	return items
}

// buildLargeHostSet synthesizes a large nmap-style host/port result set.
func buildLargeHostSet(n int) []model.Item {
	items := make([]model.Item, 0, n)
	services := []string{"microsoft-ds", "ssh", "http", "https", "mysql", "unknown", "rdp", "ldap"}
	for i := 0; i < n; i++ {
		items = append(items, model.Item{
			Kind: model.KindHost, Address: "10.0.0.1", Port: 10000 + i,
			Service: services[i%len(services)], Banner: fmt.Sprintf("Service %d.%d.%d", i%6, i%10, i%20),
		})
	}
	return items
}

// BenchmarkEvaluateFFUF_Parallel exercises the real Evaluate() path (which
// dispatches to the worker pool once item count crosses parallelThreshold)
// against a large ffuf-scale dataset.
func BenchmarkEvaluateFFUF_Parallel(b *testing.B) {
	rs, _, err := Load("")
	if err != nil {
		b.Fatal(err)
	}
	items := buildLargeFFUFSet(50000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rs.Evaluate(items)
	}
}

// BenchmarkEvaluateFFUF_Sequential forces the sequential inner loop on the
// SAME dataset (bypassing the worker-pool dispatch) to give a direct,
// apples-to-apples comparison of the parallelization's wall-clock benefit via
// `go test -bench=. -benchtime=3x -cpu=1,4,8`.
func BenchmarkEvaluateFFUF_Sequential(b *testing.B) {
	rs, _, err := Load("")
	if err != nil {
		b.Fatal(err)
	}
	items := buildLargeFFUFSet(50000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findings := rs.evaluatePatternsRange(items)
		findings = append(findings, rs.builtinFindings(items)...)
		if rs.Builtins.Combos {
			applyCombos(findings)
		}
		_ = dedupe(findings)
	}
}

// BenchmarkEvaluateHosts_Parallel benchmarks the host-kind path at scale (a
// very large combined nmap scan across many hosts).
func BenchmarkEvaluateHosts_Parallel(b *testing.B) {
	rs, _, err := Load("")
	if err != nil {
		b.Fatal(err)
	}
	items := buildLargeHostSet(20000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rs.Evaluate(items)
	}
}

// BenchmarkEvaluateHosts_Sequential is the sequential counterpart for the same
// host-scale dataset.
func BenchmarkEvaluateHosts_Sequential(b *testing.B) {
	rs, _, err := Load("")
	if err != nil {
		b.Fatal(err)
	}
	items := buildLargeHostSet(20000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findings := rs.evaluatePatternsRange(items)
		findings = append(findings, rs.builtinFindings(items)...)
		if rs.Builtins.Combos {
			applyCombos(findings)
		}
		_ = dedupe(findings)
	}
}
