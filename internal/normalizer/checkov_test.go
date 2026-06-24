package normalizer

import (
	"testing"

	"github.com/shfahiim/cyberai/internal/model"
)

func TestCheckov(t *testing.T) {
	raw := []byte(`{
	  "results": {
	    "failed_checks": [
	      {
	        "check_id": "CKV_AWS_20",
	        "check_name": "S3 Bucket has an ACL defined which allows public READ access.",
	        "file_path": "/terraform/main.tf",
	        "file_line_range": [7, 11],
	        "resource": "aws_s3_bucket.public",
	        "guideline": "https://docs.bridgecrew.io/docs/s3_1-acl-read-permissions-everyone",
	        "severity": "HIGH",
	        "cwe": ["CWE-732"]
	      }
	    ]
	  }
	}`)
	findings, err := Checkov(raw)
	if err != nil {
		t.Fatalf("Checkov: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Tool != "checkov" || f.RuleID != "CKV_AWS_20" {
		t.Fatalf("unexpected finding identity: %+v", f)
	}
	if f.Category != model.CategoryIaC || f.Severity != model.SeverityHigh {
		t.Fatalf("category/severity = %s/%s", f.Category, f.Severity)
	}
	if f.File != "terraform/main.tf" || f.StartLine != 7 || f.EndLine != 11 {
		t.Fatalf("location = %s:%d-%d", f.File, f.StartLine, f.EndLine)
	}
}
