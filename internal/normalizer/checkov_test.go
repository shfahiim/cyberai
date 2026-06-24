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

func TestCheckovArray(t *testing.T) {
	raw := []byte(`[
		{
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
		},
		{
			"results": {
				"failed_checks": [
					{
						"check_id": "CKV_K8S_21",
						"check_name": "Read-only root filesystem",
						"file_path": "/k8s/deployment.yaml",
						"file_line_range": [15, 15],
						"resource": "Deployment.api",
						"severity": "MEDIUM"
					}
				]
			}
		}
	]`)
	findings, err := Checkov(raw)
	if err != nil {
		t.Fatalf("Checkov: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d, want 2", len(findings))
	}
	f1 := findings[0]
	if f1.Tool != "checkov" || f1.RuleID != "CKV_AWS_20" {
		t.Fatalf("unexpected f1: %+v", f1)
	}
	f2 := findings[1]
	if f2.Tool != "checkov" || f2.RuleID != "CKV_K8S_21" {
		t.Fatalf("unexpected f2: %+v", f2)
	}
}
