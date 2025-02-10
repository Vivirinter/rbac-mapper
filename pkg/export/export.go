package export

import (
	"encoding/json"
	"fmt"

	"github.com/Vivirinter/rbac-mapper/pkg/analyzer"
	"github.com/Vivirinter/rbac-mapper/pkg/formatter"
	"gopkg.in/yaml.v2"
)

type Format string

const (
	TextFormat Format = "text"
	JSONFormat Format = "json"
	YAMLFormat Format = "yaml"
)

var (
	ErrNilResult     = fmt.Errorf("nil result")
	ErrInvalidFormat = fmt.Errorf("invalid format")
)

func Export(result analyzer.Result, format Format) error {
	if err := validateFormat(format); err != nil {
		return fmt.Errorf("validating format: %w", err)
	}

	switch format {
	case TextFormat:
		fmt.Print(formatter.FormatRoles(&result))
		fmt.Print(formatter.FormatBindings(&result))
		fmt.Print(formatter.FormatSummary(&result))
	case JSONFormat:
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling to JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	case YAMLFormat:
		yamlData, err := yaml.Marshal(result)
		if err != nil {
			return fmt.Errorf("marshaling to YAML: %w", err)
		}
		fmt.Println(string(yamlData))
	}

	return nil
}

func validateFormat(format Format) error {
	switch format {
	case TextFormat, JSONFormat, YAMLFormat:
		return nil
	default:
		return ErrInvalidFormat
	}
}
