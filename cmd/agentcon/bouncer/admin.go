package bouncer

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/approval"
	"github.com/pastdev/agentcon/pkg/bouncer/host"
	"github.com/pastdev/agentcon/pkg/bouncer/prompt"
	"github.com/spf13/cobra"
)

func promptsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "prompts",
		Short: "List pending prompts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := dial()
			if err != nil {
				return err
			}
			list, err := c.Prompts(cmd.Context())
			if err != nil {
				return fmt.Errorf("prompts: %w", err)
			}
			if len(list) == 0 {
				fmt.Println("no pending prompts")
				return nil
			}
			d := approval.Display
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "ID\tKIND\tSOURCE\tSESSION\tMESSAGE\tDETAIL\tEXPIRES")
			for _, p := range list {
				detail := d(p.Detail, 80)
				if p.Origin != "" {
					detail += " (" + d(p.Origin, 80) + ")"
				}
				if p.Claim != nil {
					claim, cut := approval.ClaimSummary(*p.Claim, 80)
					if cut {
						claim += " (agentcon bouncer answer " + p.ID + " shows it in full)"
					}
					detail = "claim " + claim + "; " + detail
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.ID, p.Kind, d(p.Source, 60), d(p.SessionLabel, 60),
					d(p.Message, 80), detail, time.Until(p.Expires).Round(time.Second))
			}
			return w.Flush()
		},
	}
}

func answerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "answer ID",
		Short: "Answer a pending prompt at this terminal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := dial()
			if err != nil {
				return err
			}
			list, err := c.Prompts(cmd.Context())
			if err != nil {
				return fmt.Errorf("prompts: %w", err)
			}
			for _, p := range list {
				if p.ID == args[0] {
					return host.AnswerAtTerminal(cmd.Context(), c, os.Stdin, os.Stderr, p)
				}
			}
			return fmt.Errorf("no pending prompt %s", args[0])
		},
	}
}

func declineCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "decline ID",
		Short: "Refuse to answer a pending prompt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := dial()
			if err != nil {
				return err
			}
			return c.DeclinePrompt(cmd.Context(), args[0])
		},
	}
}

func approveCmd(allow bool) *cobra.Command {
	var session bool
	use, short := "approve ID", "Approve a pending request"
	if !allow {
		use, short = "deny ID", "Deny a pending request"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := dial()
			if err != nil {
				return err
			}
			return c.AnswerPrompt(cmd.Context(), args[0], prompt.Answer{Allow: allow, Remember: session})
		},
	}
	help := "apply to identical requests for the rest of the session"
	if allow {
		help += "; for a claim request, add the claim to the session"
	}
	cmd.Flags().BoolVarP(&session, "session", "s", false, help)
	return cmd
}

func sessionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "List agent sessions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := dial()
			if err != nil {
				return err
			}
			list, err := c.Sessions(cmd.Context())
			if err != nil {
				return fmt.Errorf("sessions: %w", err)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "ID\tLABEL\tPROFILE\tCREATED\tCLAIMS")
			for _, s := range list {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", s.ID, s.Label, s.Profile, s.Created.Format(time.DateTime), s.Claims.Count())
			}
			return w.Flush()
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "end ID",
		Short: "Revoke a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := dial()
			if err != nil {
				return err
			}
			return c.EndSession(cmd.Context(), args[0])
		},
	})
	return cmd
}

func checkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Validate the config and compile every filter",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			svc, err := loadBouncerService()
			if err != nil {
				return err
			}
			got, err := host.Check(svc)
			if err != nil {
				return fmt.Errorf("check: %w", err)
			}
			for _, p := range got.Profiles {
				fmt.Printf("profile %-14s %d http, %d ssh, unmatched=%s\n", p.Name, p.HTTP, p.SSH, p.Unmatched)
			}
			fmt.Printf("ok: %s\n", got.Path)
			return nil
		},
	}
}
