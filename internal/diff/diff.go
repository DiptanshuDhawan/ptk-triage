// Package diff compares two scans and surfaces only what changed between them.
//
// Re-running scans as an engagement progresses is routine; re-reading the whole
// report each time is not. Diff mode answers "what is new or different since
// last time" so attention goes to the delta. It reports:
//
//   - added     items present in new but not old (new ports/paths/subs)
//   - removed   items present in old but not new (service went away, host down)
//   - changed   same item key, but a meaningful field changed:
//   - host: service/banner/version changed (e.g. patched/upgraded)
//   - path: status or response size changed
//   - sub:  resolution/CNAME/dangling state changed, incl. the
//     high-value "dangling CNAME became live" and
//     "live CNAME became dangling (new takeover window)"
//
// Items are matched by model.Item.Key(). The result is itself expressed as
// Findings so it flows through the same reporter.
package diff

import (
	"fmt"
	"strings"

	"ptk/internal/model"
)

// Change categorizes a single delta.
type Change struct {
	Type   string // "added" | "removed" | "changed"
	Item   model.Item
	Detail string
}

// Result holds all deltas between two scans.
type Result struct {
	Added   []Change
	Removed []Change
	Changed []Change
}

// Compute diffs old vs new.
func Compute(oldItems, newItems []model.Item) Result {
	oldByKey := index(oldItems)
	newByKey := index(newItems)

	var res Result

	for k, ni := range newByKey {
		oi, ok := oldByKey[k]
		if !ok {
			res.Added = append(res.Added, Change{Type: "added", Item: ni, Detail: addedDetail(ni)})
			continue
		}
		if d := changeDetail(oi, ni); d != "" {
			res.Changed = append(res.Changed, Change{Type: "changed", Item: ni, Detail: d})
		}
	}
	for k, oi := range oldByKey {
		if _, ok := newByKey[k]; !ok {
			res.Removed = append(res.Removed, Change{Type: "removed", Item: oi, Detail: removedDetail(oi)})
		}
	}
	return res
}

func index(items []model.Item) map[string]model.Item {
	m := make(map[string]model.Item, len(items))
	for _, it := range items {
		m[it.Key()] = it
	}
	return m
}

func addedDetail(it model.Item) string {
	switch it.Kind {
	case model.KindHost:
		svc := it.Service
		if svc == "" {
			svc = "unknown service"
		}
		return fmt.Sprintf("new open port — %s %s", svc, strings.TrimSpace(it.Banner))
	case model.KindPath:
		return fmt.Sprintf("new path — status %d, %dB", it.Status, it.Length)
	case model.KindSub:
		if it.Resolved {
			return fmt.Sprintf("new subdomain — resolves to %s", it.Address)
		}
		return "new subdomain"
	}
	return "new item"
}

func removedDetail(it model.Item) string {
	switch it.Kind {
	case model.KindHost:
		return fmt.Sprintf("port no longer open — was %s", it.Service)
	case model.KindPath:
		return "path no longer present"
	case model.KindSub:
		return "subdomain no longer present"
	}
	return "item removed"
}

// changeDetail returns a human description of what changed, or "" if nothing
// meaningful did.
func changeDetail(old, new model.Item) string {
	switch new.Kind {
	case model.KindHost:
		var parts []string
		if old.Service != new.Service {
			parts = append(parts, fmt.Sprintf("service %q -> %q", old.Service, new.Service))
		}
		if old.Banner != new.Banner && (old.Banner != "" || new.Banner != "") {
			parts = append(parts, fmt.Sprintf("banner %q -> %q", old.Banner, new.Banner))
		}
		if len(parts) > 0 {
			return strings.Join(parts, "; ")
		}
	case model.KindPath:
		var parts []string
		if old.Status != new.Status {
			parts = append(parts, fmt.Sprintf("status %d -> %d", old.Status, new.Status))
		}
		if old.Length != new.Length {
			parts = append(parts, fmt.Sprintf("size %dB -> %dB", old.Length, new.Length))
		}
		if len(parts) > 0 {
			return strings.Join(parts, "; ")
		}
	case model.KindSub:
		// The most valuable sub transitions get explicit, prominent wording.
		oldDangling := old.Dangling || (old.CNAME != "" && !old.Resolved)
		newDangling := new.Dangling || (new.CNAME != "" && !new.Resolved)
		switch {
		case oldDangling && !newDangling:
			return fmt.Sprintf("CNAME now resolves (%s) — previously dangling, takeover window likely closed", new.Address)
		case !oldDangling && newDangling:
			return fmt.Sprintf("CNAME became dangling (-> %s) — NEW possible subdomain takeover", new.CNAME)
		}
		var parts []string
		if old.Resolved != new.Resolved {
			if new.Resolved {
				parts = append(parts, fmt.Sprintf("now resolves to %s", new.Address))
			} else {
				parts = append(parts, "no longer resolves")
			}
		} else if old.Address != new.Address && new.Address != "" {
			parts = append(parts, fmt.Sprintf("IP %s -> %s", old.Address, new.Address))
		}
		if old.Status != new.Status && new.Status != 0 {
			parts = append(parts, fmt.Sprintf("http %d -> %d", old.Status, new.Status))
		}
		if len(parts) > 0 {
			return strings.Join(parts, "; ")
		}
	}
	return ""
}

// ToFindings converts a diff Result into severity-ranked Findings so it can be
// rendered by the normal reporter. Severity reflects actionability: a new
// dangling CNAME is HIGH, new ports/paths are MED, removals are INFO.
func (r Result) ToFindings() []model.Finding {
	var fs []model.Finding
	mk := func(c Change, sev model.Severity, rule, prefix string) model.Finding {
		return model.Finding{
			Item:     c.Item,
			Kind:     c.Item.Kind,
			Target:   c.Item.Target(),
			Severity: sev,
			SevLabel: sev.String(),
			RuleID:   rule,
			Reason:   prefix + c.Detail,
		}
	}
	for _, c := range r.Added {
		sev := model.SevMedium
		if c.Item.Kind == model.KindSub && !c.Item.Resolved {
			sev = model.SevLow
		}
		fs = append(fs, mk(c, sev, "diff-added", "+ "))
	}
	for _, c := range r.Changed {
		sev := model.SevLow
		// Promote the two takeover-related transitions.
		if strings.Contains(c.Detail, "NEW possible subdomain takeover") {
			sev = model.SevHigh
		} else if strings.Contains(c.Detail, "service") || strings.Contains(c.Detail, "status") {
			sev = model.SevMedium
		}
		fs = append(fs, mk(c, sev, "diff-changed", "~ "))
	}
	for _, c := range r.Removed {
		fs = append(fs, mk(c, model.SevInfo, "diff-removed", "- "))
	}
	model.SortFindings(fs)
	return fs
}

// Counts summarizes the diff for a header line.
func (r Result) Counts() (added, removed, changed int) {
	return len(r.Added), len(r.Removed), len(r.Changed)
}
