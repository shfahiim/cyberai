package cli

import "testing"

func TestNormalizeCategories_Aliases(t *testing.T) {
	got, err := normalizeCategories([]string{"code", "dependencies", "pipelines"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sast", "sca", "cicd"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestNormalizeCategories_Unknown(t *testing.T) {
	if _, err := normalizeCategories([]string{"banana"}); err == nil {
		t.Fatal("expected error for unknown category")
	}
}

func TestShouldSaveReports(t *testing.T) {
	cmd := newScanCmd()
	opts := &scanOptions{}
	if shouldSaveReports(opts, cmd) {
		t.Fatal("default scan should not save reports")
	}
	opts.Save = true
	if !shouldSaveReports(opts, cmd) {
		t.Fatal("--save should write reports")
	}
}

func TestApplyScanPreset_CI(t *testing.T) {
	cmd := newScanCmd()
	opts := &scanOptions{Preset: "ci"}
	if err := applyScanPreset(opts, cmd); err != nil {
		t.Fatal(err)
	}
	if !opts.CI || !opts.Enrich || !opts.Save {
		t.Fatalf("ci preset = %+v", opts)
	}
	if len(opts.Formats) != 3 {
		t.Fatalf("formats = %v", opts.Formats)
	}
}
