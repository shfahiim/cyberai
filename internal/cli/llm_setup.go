package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/shfahiim/cyberai/internal/config"
	"github.com/shfahiim/cyberai/internal/llm"
	"github.com/shfahiim/cyberai/internal/ui"
)

func prepareLLMSession(cmd *cobra.Command, cfg *config.Config, llmEnabled bool, pickModel bool) error {
	cfg.LLM.Provider = llm.ResolveProvider(cfg.LLM.Provider)
	cfg.LLM.Model = llm.ResolveModel(cfg.LLM.Provider, cfg.LLM.Model)

	if pickModel && !llmEnabled {
		return errf(cmd, "--pick-model requires LLM to be enabled")
	}
	if pickModel && !isInteractiveStdin() {
		return errf(cmd, "--pick-model requires an interactive terminal")
	}
	if !llmEnabled || !isInteractiveStdin() {
		return nil
	}

	key, _ := llm.LookupAPIKey(cfg.LLM.Provider)
	if key == "" {
		entered, err := promptLLMAPIKey(cmd, cfg.LLM.Provider)
		if err != nil {
			return err
		}
		if entered != "" {
			if env := llm.PreferredAPIKeyEnv(cfg.LLM.Provider); env != "" {
				_ = os.Setenv(env, entered)
			}
			// Save entered key to global config
			globalCfg, err := llm.LoadGlobalConfig()
			if err == nil {
				globalCfg.APIKeys[cfg.LLM.Provider] = entered
				_ = llm.SaveGlobalConfig(globalCfg)
			}

			if !cmd.Flags().Changed("model") {
				model, err := promptLLMModel(cmd, cfg.LLM.Provider, cfg.LLM.Model)
				if err != nil {
					return err
				}
				cfg.LLM.Model = model

				// Save selected model to global config
				globalCfg, err = llm.LoadGlobalConfig()
				if err == nil {
					globalCfg.Models[cfg.LLM.Provider] = model
					_ = llm.SaveGlobalConfig(globalCfg)
				}
			}
		}
		return nil
	}

	if pickModel && !cmd.Flags().Changed("model") {
		model, err := promptLLMModel(cmd, cfg.LLM.Provider, cfg.LLM.Model)
		if err != nil {
			return err
		}
		cfg.LLM.Model = model

		// Save selected model to global config
		globalCfg, err := llm.LoadGlobalConfig()
		if err == nil {
			globalCfg.Models[cfg.LLM.Provider] = model
			_ = llm.SaveGlobalConfig(globalCfg)
		}
	}

	return nil
}

func isInteractiveStdin() bool {
	return ui.IsTerminal(os.Stdin.Fd())
}

func promptLLMAPIKey(cmd *cobra.Command, provider string) (string, error) {
	uiR := uiFrom(cmd)
	w := cmd.ErrOrStderr()

	title := fmt.Sprintf("%s API key not found.", displayProviderName(provider))
	if uiR != nil {
		title = uiR.WarningStyle().Render(title)
	}
	fmt.Fprintln(w, title)
	fmt.Fprintf(w, "Enter a key to enable %s routing and HTML summaries for this run.\n", provider)
	fmt.Fprint(w, "API key (hidden; press Enter to continue without LLM): ")

	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(w)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func promptLLMModel(cmd *cobra.Command, provider, current string) (string, error) {
	models := llm.SupportedModels(provider)
	w := cmd.ErrOrStderr()

	fmt.Fprintf(w, "Select %s model for this run:\n", provider)
	for i, model := range models {
		currentTag := ""
		if model.ID == current {
			currentTag = " [current]"
		}
		fmt.Fprintf(w, "  %d. %s (%s)%s\n", i+1, model.ID, model.Status, currentTag)
		fmt.Fprintf(w, "     %s\n", model.Description)
	}

	reader := bufio.NewReader(cmd.InOrStdin())
	for {
		fmt.Fprintf(w, "Model [%s]: ", current)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return current, nil
		}
		if idx, err := strconv.Atoi(line); err == nil {
			if idx >= 1 && idx <= len(models) {
				return models[idx-1].ID, nil
			}
		}
		for _, model := range models {
			if line == model.ID {
				return model.ID, nil
			}
		}
		if strings.HasPrefix(line, provider+"-") || strings.HasPrefix(line, "gemini-") {
			return line, nil
		}
		fmt.Fprintln(w, "Enter a number from the list or a full model ID.")
	}
}

func displayProviderName(provider string) string {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return "LLM"
	}
	return strings.ToUpper(provider[:1]) + provider[1:]
}
