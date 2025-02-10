# RBAC Mapper

Kubernetes RBAC permissions analyzer and visualizer.

## Quick Start

```bash
# Install
go install github.com/Vivirinter/rbac-mapper@latest

# Run (requires valid kubeconfig)
./rbac-mapper

# Show help
./rbac-mapper --help

# Filter by verbs and resources
./rbac-mapper --verbs=get,list --resources=pods

# Change output format
./rbac-mapper --output-format=json
```

## Flags

- `--kubeconfig`: Path to kubeconfig file (default: $HOME/.kube/config)
- `--output-format`: Output format (text, json, yaml)
- `--verbs`: Filter by verbs (comma-separated)
- `--resources`: Filter by resources (comma-separated)
- `--limit`: Limit the number of results (0 for no limit)

## License

MIT License - see [LICENSE](LICENSE) file
