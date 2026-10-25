package graphite

// Round 39 (campaign 14): the cross-language conformance corpus,
// examples/decisions/conformance.json, read the way this SDK reads a server's
// answer — DecodeVerificationResult, then IsExecutable — and held to the
// outcome the corpus names for Go. The Rust Core, the TypeScript SDK and the
// agent guard read the same file; see its "doc".

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type corpusEdit struct {
	Op    string            `json:"op"`
	Path  []json.RawMessage `json:"path"`
	Value json.RawMessage   `json:"value"`
}

type corpusOutcomes struct {
	Rust string `json:"rust"`
	TS   string `json:"ts"`
	Go   string `json:"go"`
}

type corpusVector struct {
	Name       string         `json:"name"`
	Base       string         `json:"base"`
	RawReplace [][2]string    `json:"raw_replace"`
	Edits      []corpusEdit   `json:"edits"`
	Expect     corpusOutcomes `json:"expect"`
	Note       string         `json:"note"`
}

type conformanceCorpus struct {
	Version     int            `json:"version"`
	Verdicts    []corpusVector `json:"verdicts"`
	ContentHash []struct {
		Name          string          `json:"name"`
		ProgramID     string          `json:"program_id"`
		Discriminator string          `json:"discriminator"`
		Accounts      []string        `json:"accounts"`
		Data          json.RawMessage `json:"data"`
		CPITargets    []string        `json:"cpi_targets"`
		Expect        json.RawMessage `json:"expect"`
		DiffersFrom   string          `json:"differs_from"`
	} `json:"content_hash"`
	TransactionDigest []struct {
		Name   string         `json:"name"`
		Hex    string         `json:"hex"`
		Expect corpusOutcomes `json:"expect"`
	} `json:"transaction_digest"`
}

func loadCorpus(t *testing.T) conformanceCorpus {
	t.Helper()
	raw, err := os.ReadFile("../../examples/decisions/conformance.json")
	if err != nil {
		t.Fatal(err)
	}
	var c conformanceCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || len(c.Verdicts) < 90 {
		t.Fatalf("corpus version %d with %d verdict vectors", c.Version, len(c.Verdicts))
	}
	return c
}

// vectorText is the committed verdict a vector starts from, with its exact
// text replacements applied (each must occur exactly once).
func vectorText(t *testing.T, v corpusVector) []byte {
	t.Helper()
	text := string(decisionFixture(t, v.Base))
	for _, r := range v.RawReplace {
		if strings.Count(text, r[0]) != 1 {
			t.Fatalf("%s: %q must occur exactly once", v.Name, r[0])
		}
		text = strings.Replace(text, r[0], r[1], 1)
	}
	return []byte(text)
}

// applyEdits applies the vector's set / delete / push edits to a decoded
// verdict. Numbers stay json.Number, so nothing is rounded on the way back.
func applyEdits(t *testing.T, v corpusVector, doc any) {
	t.Helper()
	decodeValue := func(raw json.RawMessage) any {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var out any
		if err := dec.Decode(&out); err != nil {
			t.Fatalf("%s: edit value: %v", v.Name, err)
		}
		return out
	}
	for _, e := range v.Edits {
		at := doc
		for i, step := range e.Path {
			last := i == len(e.Path)-1
			var key string
			var index int
			isIndex := json.Unmarshal(step, &index) == nil
			if !isIndex {
				if err := json.Unmarshal(step, &key); err != nil {
					t.Fatalf("%s: path step %s", v.Name, step)
				}
			}
			if !last {
				if isIndex {
					at = at.([]any)[index]
				} else {
					at = at.(map[string]any)[key]
				}
				continue
			}
			switch e.Op {
			case "set":
				if isIndex {
					at.([]any)[index] = decodeValue(e.Value)
				} else {
					at.(map[string]any)[key] = decodeValue(e.Value)
				}
			case "delete":
				delete(at.(map[string]any), key)
			case "push":
				m := at.(map[string]any)
				m[key] = append(m[key].([]any), decodeValue(e.Value))
			default:
				t.Fatalf("%s: unknown edit %q", v.Name, e.Op)
			}
		}
	}
}

func goOutcome(t *testing.T, v corpusVector) string {
	t.Helper()
	if len(v.RawReplace) > 0 && len(v.Edits) > 0 {
		t.Fatalf("%s: a vector is either raw text or edits, not both", v.Name)
	}
	body := vectorText(t, v)
	if len(v.Edits) > 0 {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var doc any
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		applyEdits(t, v, doc)
		var err error
		if body, err = json.Marshal(doc); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
	}
	r, err := DecodeVerificationResult(body)
	if err != nil {
		if !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("%s: a refusal that is not ErrInvalidResponse: %v", v.Name, err)
		}
		return "unreadable"
	}
	if r.IsExecutable() {
		return "executable"
	}
	return "not_executable"
}

func TestRound39CorpusEveryVerdictVectorReadsInGoAsTheCorpusSays(t *testing.T) {
	c := loadCorpus(t)
	for _, v := range c.Verdicts {
		if got := goOutcome(t, v); got != v.Expect.Go {
			t.Errorf("%s: expected %s, got %s", v.Name, v.Expect.Go, got)
		}
		// Never looser than the Core's own rule.
		if v.Expect.Go == "executable" && v.Expect.Rust != "executable" {
			t.Errorf("%s: Go executable where the Core's rule is not", v.Name)
		}
	}
}

func TestRound39CorpusContentHashes(t *testing.T) {
	c := loadCorpus(t)
	got := map[string]string{}
	for _, v := range c.ContentHash {
		var expect string
		_ = json.Unmarshal(v.Expect, &expect)
		hash := "error"
		var data ByteArray
		if string(v.Data) == "null" || data.UnmarshalJSON(v.Data) == nil {
			hash = ComputeContentHash(AuditBindParams{
				ProgramID:                v.ProgramID,
				InstructionDiscriminator: v.Discriminator,
				AccountAddresses:         v.Accounts,
				InstructionData:          data,
				CPITargets:               v.CPITargets,
			})
		}
		got[v.Name] = hash
		if hash != expect {
			t.Errorf("%s: %s, want %s", v.Name, hash, expect)
		}
	}
	for _, v := range c.ContentHash {
		if v.DiffersFrom != "" && got[v.Name] == got[v.DiffersFrom] {
			t.Errorf("%s hashes like %s", v.Name, v.DiffersFrom)
		}
	}
}

func TestRound39CorpusTransactionDigests(t *testing.T) {
	c := loadCorpus(t)
	for _, d := range c.TransactionDigest {
		raw, err := hex.DecodeString(d.Hex)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := TransactionDigest(raw)
		if err != nil {
			if !errors.Is(err, ErrAuditBind) {
				t.Fatalf("%s: %v", d.Name, err)
			}
			digest = "error"
		}
		if digest != d.Expect.Go {
			t.Errorf("%s: %s, want %s", d.Name, digest, d.Expect.Go)
		}
		if d.Expect.Rust != "error" && digest != d.Expect.Rust && digest != "error" {
			t.Errorf("%s: differs from the Core", d.Name)
		}
	}
}
