package export

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Vivirinter/rbac-mapper/pkg/analyzer"
	"github.com/Vivirinter/rbac-mapper/pkg/formatter"
	"gopkg.in/yaml.v2"
)

const (
	FormatText = "text"
	FormatJSON = "json"
	FormatYAML = "yaml"
)

func Result(result *analyzer.AnalysisResult, format string, useColor bool) error {
	if result == nil {
		return fmt.Errorf("result cannot be nil")
	}

	var output string
	var err error

	switch format {
	case FormatText, "":
		output = formatter.NewFormatter(useColor).FormatAnalysis(result)
	case FormatJSON:
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling to JSON: %w", err)
		}
		output = string(data) + "\n"
	case FormatYAML:
		data, err := yaml.Marshal(result)
		if err != nil {
			return fmt.Errorf("marshaling to YAML: %w", err)
		}
		output = string(data)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("exporting result: %w", err)
	}

	if _, err := os.Stdout.WriteString(output); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	return nil
}
