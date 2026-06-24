package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/shfahiim/cyberai/internal/suppression"
)

// newSuppressCmd returns the `suppress` command with add/list/remove
// subcommands. Calling `suppress <finding-id> --reason ...` directly (no
// subcommand) is equivalent to `suppress add <finding-id> --reason ...`.
func newSuppressCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "suppress [finding-id]",
		Short: "Manage finding suppressions",
		Long: strings.Join([]string{
			"Manage .cyberai-suppressions.yaml in the project root.",
			"",
			"Suppressions hide known false positives from future scan output.",
			"Match by finding ID (F-…) or by rule ID with optional path glob.",
			"",
			"Examples:",
			"  cyberai suppress F-a1b2c3d4 --reason \"false positive\"",
			"  cyberai suppress add --rule-id python.sql-injection --reason \"mitigated\" --expires 90d",
			"  cyberai suppress list",
			"  cyberai suppress remove S-deadbeef",
			"",
			"After scanning, terminal output includes suppress hints when enabled.",
		}, "\n"),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				addCmd := newSuppressAddCmd()
				addArgs := []string{args[0]}
				for _, name := range []string{"reason", "author", "ticket", "expires", "rule-id", "path", "target"} {
					if !cmd.Flags().Changed(name) {
						continue
					}
					val, err := cmd.Flags().GetString(name)
					if err != nil {
						return err
					}
					addArgs = append(addArgs, "--"+name, val)
				}
				addCmd.SetArgs(addArgs)
				addCmd.SetOut(cmd.OutOrStdout())
				addCmd.SetErr(cmd.ErrOrStderr())
				return addCmd.Execute()
			}
			return cmd.Help()
		},
	}

	// Wire up the common --reason / --expires flags on the parent so that
	// `suppress <id> --reason "..."` works without a subcommand.
	cmd.Flags().String("reason", "", "justification for the suppression (required)")
	cmd.Flags().String("author", "", "person adding the suppression")
	cmd.Flags().String("ticket", "", "tracker link or issue reference")
	cmd.Flags().String("expires", "", "expiry: 30d | 90d | 1y | YYYY-MM-DD")
	cmd.Flags().String("rule-id", "", "suppress all findings from this rule ID")
	cmd.Flags().String("path", "", "file glob to scope a rule-id suppression")
	cmd.Flags().String("target", ".", "project root directory")

	cmd.AddCommand(
		newSuppressAddCmd(),
		newSuppressListCmd(),
		newSuppressRemoveCmd(),
	)

	return cmd
}

// newSuppressAddCmd returns the `suppress add` subcommand.
func newSuppressAddCmd() *cobra.Command {
	var (
		reason  string
		author  string
		ticket  string
		expires string
		ruleID  string
		path    string
		target  string
	)

	cmd := &cobra.Command{
		Use:   "add [finding-id]",
		Short: "Add a suppression",
		Long: `Add a suppression to .cyberai-suppressions.yaml.

Provide either a finding ID (positional argument) or --rule-id to match all
findings from a rule.  --path can further constrain a rule-id suppression to
a specific file or glob pattern.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if reason == "" {
				return errf(cmd, "--reason is required")
			}

			findingID := ""
			if len(args) == 1 {
				findingID = args[0]
			}

			if findingID == "" && ruleID == "" {
				return errf(cmd, "provide a finding-id argument or --rule-id")
			}

			var expiry time.Time
			if expires != "" {
				var err error
				expiry, err = parseExpiry(expires)
				if err != nil {
					return errf(cmd, "invalid --expires %q: %v", expires, err)
				}
			}

			root, err := resolveTarget(target)
			if err != nil {
				return err
			}

			sf, err := suppression.Load(root)
			if err != nil {
				return err
			}

			s := suppression.Suppression{
				FindingID: findingID,
				RuleID:    ruleID,
				Path:      path,
				Reason:    reason,
				Author:    author,
				Ticket:    ticket,
				ExpiresAt: expiry,
			}

			if err := sf.Add(s); err != nil {
				return err
			}

			// Print the ID of the newly-created suppression.
			added := sf.Suppressions[len(sf.Suppressions)-1]
			fmt.Fprintf(cmd.OutOrStdout(), "suppression added: %s\n", added.ID)
			return nil
		},
	}

	cmd.Flags().StringVar(&reason, "reason", "", "justification (required)")
	cmd.Flags().StringVar(&author, "author", "", "person adding the suppression")
	cmd.Flags().StringVar(&ticket, "ticket", "", "tracker link or issue reference")
	cmd.Flags().StringVar(&expires, "expires", "", "expiry: 30d | 90d | 1y | YYYY-MM-DD")
	cmd.Flags().StringVar(&ruleID, "rule-id", "", "suppress all findings from this rule")
	cmd.Flags().StringVar(&path, "path", "", "file glob to scope a rule-id suppression")
	cmd.Flags().StringVar(&target, "target", ".", "project root directory")

	return cmd
}

// newSuppressListCmd returns the `suppress list` subcommand.
func newSuppressListCmd() *cobra.Command {
	var target string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all suppressions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := resolveTarget(target)
			if err != nil {
				return err
			}

			sf, err := suppression.Load(root)
			if err != nil {
				return err
			}

			if len(sf.Suppressions) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no suppressions found")
				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tTARGET\tREASON\tEXPIRES\tSTATUS")
			fmt.Fprintln(w, strings.Repeat("-", 80))

			for _, s := range sf.Suppressions {
				target := s.FindingID
				if target == "" {
					target = s.RuleID
					if s.Path != "" {
						target += " (" + s.Path + ")"
					}
				}

				expiresStr := "never"
				if !s.ExpiresAt.IsZero() {
					expiresStr = s.ExpiresAt.Format("2006-01-02")
				}

				status := "active"
				if s.IsExpired() {
					status = "EXPIRED"
				}

				reason := s.Reason
				if len(reason) > 40 {
					reason = reason[:37] + "..."
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					s.ID, target, reason, expiresStr, status)
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&target, "target", ".", "project root directory")
	return cmd
}

// newSuppressRemoveCmd returns the `suppress remove` subcommand.
func newSuppressRemoveCmd() *cobra.Command {
	var target string

	cmd := &cobra.Command{
		Use:     "remove <id>",
		Aliases: []string{"rm", "delete"},
		Short:   "Remove a suppression by ID",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := resolveTarget(target)
			if err != nil {
				return err
			}

			sf, err := suppression.Load(root)
			if err != nil {
				return err
			}

			id := args[0]
			if err := sf.Remove(id); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "suppression %s removed\n", id)
			return nil
		},
	}

	cmd.Flags().StringVar(&target, "target", ".", "project root directory")
	return cmd
}

// parseExpiry parses an expiry string in one of the supported formats:
// "30d", "90d", "1y", or "YYYY-MM-DD".
func parseExpiry(s string) (time.Time, error) {
	now := time.Now().UTC()
	switch strings.ToLower(s) {
	case "30d":
		return now.AddDate(0, 0, 30), nil
	case "90d":
		return now.AddDate(0, 0, 90), nil
	case "1y":
		return now.AddDate(1, 0, 0), nil
	}
	// Try YYYY-MM-DD
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("expected 30d, 90d, 1y, or YYYY-MM-DD; got %q", s)
	}
	return t.UTC(), nil
}
