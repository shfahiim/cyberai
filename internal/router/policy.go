package router

import "github.com/shfahiim/cyberai/internal/project"

func DefaultSemgrepRulesets(p *project.Profile) []string {
	configs := []string{"p/security-audit", "p/owasp-top-ten"}
	if p == nil {
		return configs
	}
	for _, lang := range p.Languages {
		switch lang {
		case "go":
			configs = append(configs, "p/golang")
		case "javascript":
			configs = append(configs, "p/javascript", "p/nodejs")
		case "typescript":
			configs = append(configs, "p/typescript")
		case "python":
			configs = append(configs, "p/python")
		case "rust":
			configs = append(configs, "p/rust")
		case "java":
			configs = append(configs, "p/java")
		case "ruby":
			configs = append(configs, "p/ruby")
		case "php":
			configs = append(configs, "p/php")
		}
	}
	return configs
}
