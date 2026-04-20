package models

import (
	"encoding/json"
	"testing"
)

func TestFormQuestion_IsRequired(t *testing.T) {
	tests := []struct {
		name     string
		required string
		want     bool
	}{
		{"true", "true", true},
		{"false", "false", false},
		{"conditional object", `{"operator":"OR","conditions":[{"name":"regex_condition","key":"location_type","condition":"^(GCP|Azure)$"}]}`, false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := FormQuestion{Required: json.RawMessage(tt.required)}
			if got := q.IsRequired(); got != tt.want {
				t.Errorf("IsRequired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRequestFormResponse_Unmarshal(t *testing.T) {
	raw := `{
		"requestForms": [{
			"targetCategory": "CLOUD_CONSOLE",
			"requestType": "ON_DEMAND",
			"requestForm": {
				"questions": [
					{
						"key": "reason",
						"required": true,
						"title": "Reason",
						"valueType": "TEXT",
						"validators": [{"name": "length_validator", "minLength": 0, "maxLength": 4096}]
					},
					{
						"key": "priority",
						"required": true,
						"default": "Medium",
						"title": "Priority",
						"valueType": "CHOICE",
						"valueChoices": ["High", "Medium", "Low"]
					},
					{
						"key": "org_id",
						"required": {"operator": "OR", "conditions": [{"name": "regex_condition", "key": "location_type", "condition": "^(GCP|Azure)$"}]},
						"title": "ORG Id",
						"valueType": "STRING"
					}
				]
			}
		}]
	}`

	var resp RequestFormResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(resp.RequestForms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(resp.RequestForms))
	}

	form := resp.RequestForms[0]
	if form.TargetCategory != "CLOUD_CONSOLE" {
		t.Errorf("targetCategory: got %q", form.TargetCategory)
	}
	if form.RequestType != "ON_DEMAND" {
		t.Errorf("requestType: got %q", form.RequestType)
	}

	questions := form.RequestForm.Questions
	if len(questions) != 3 {
		t.Fatalf("expected 3 questions, got %d", len(questions))
	}

	if !questions[0].IsRequired() {
		t.Error("reason should be required")
	}
	if questions[0].Title != "Reason" {
		t.Errorf("reason title: got %q", questions[0].Title)
	}
	if len(questions[0].Validators) != 1 {
		t.Fatalf("expected 1 validator for reason, got %d", len(questions[0].Validators))
	}
	if questions[0].Validators[0].Name != "length_validator" {
		t.Errorf("validator name: got %q", questions[0].Validators[0].Name)
	}

	if !questions[1].IsRequired() {
		t.Error("priority should be required")
	}
	if len(questions[1].ValueChoices) != 3 {
		t.Errorf("priority choices: expected 3, got %d", len(questions[1].ValueChoices))
	}

	if questions[2].IsRequired() {
		t.Error("org_id has conditional required, IsRequired should return false")
	}
}
