package runner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSummarizeDropsSensitiveValues(t *testing.T) {
	plan := `{"resource_changes":[
	 {"address":"module.db.aws_db_instance.x","type":"aws_db_instance","mode":"managed","change":{"actions":["create"],
	  "after":{"identifier":"db1","password":"hunter2hunter2","tags":{"a":"b"},"arn":null},
	  "after_sensitive":{"password":true},"after_unknown":{"arn":true}}},
	 {"address":"aws_s3_bucket.y","type":"aws_s3_bucket","mode":"managed","change":{"actions":["delete","create"],"after":{}}},
	 {"address":"data.aws_caller_identity.c","type":"aws_caller_identity","mode":"data","change":{"actions":["read"]}},
	 {"address":"aws_vpc.z","type":"aws_vpc","mode":"managed","change":{"actions":["no-op"]}}
	],"output_changes":{"id":{}}}`
	s, err := Summarize([]byte(plan))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "hunter2") {
		t.Fatal("sensitive value leaked into the summary")
	}
	if s.Add != 1 || s.Replace != 1 || len(s.Resources) != 2 || s.Resources[0].After["identifier"] != "db1" {
		t.Fatalf("bad summary: %s", b)
	}
}
