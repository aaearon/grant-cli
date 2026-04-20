package models

import "encoding/json"

// RequestFormResponse wraps the list of request forms returned by the API.
type RequestFormResponse struct {
	RequestForms []RequestFormEntry `json:"requestForms"`
}

// RequestFormEntry represents a single form entry for a target category and request type.
type RequestFormEntry struct {
	TargetCategory string      `json:"targetCategory"`
	RequestType    string      `json:"requestType"`
	RequestForm    RequestForm `json:"requestForm"`
}

// RequestForm contains the questions that make up an access request form.
type RequestForm struct {
	Questions []FormQuestion `json:"questions"`
}

// FormQuestion represents a single question in a request form.
type FormQuestion struct {
	Key          string          `json:"key"`
	Required     json.RawMessage `json:"required"`
	Default      interface{}     `json:"default,omitempty"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	ValueType    string          `json:"valueType,omitempty"`
	ValueChoices []interface{}   `json:"valueChoices,omitempty"`
	Validators   []Validator     `json:"validators,omitempty"`
}

// IsRequired returns true if the question is unconditionally required.
// Returns false for conditional requirements (which are JSON objects).
func (q *FormQuestion) IsRequired() bool {
	if len(q.Required) == 0 {
		return false
	}
	var b bool
	if err := json.Unmarshal(q.Required, &b); err != nil {
		return false
	}
	return b
}

// Validator represents a validation rule for a form question.
type Validator struct {
	Name         string `json:"name"`
	Regex        string `json:"regex,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
	Format       string `json:"format,omitempty"`
	MinLength    *int   `json:"minLength,omitempty"`
	MaxLength    *int   `json:"maxLength,omitempty"`
}
