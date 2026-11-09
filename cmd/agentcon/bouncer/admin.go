package bouncer

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/pastdev/agentcon/internal/bouncer/app"
	"github.com/spf13/cobra"
)

func approvalsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "approvals",
		Short: "List pending approvals",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			c, err := dial()
			if err != nil {
				return err
			}
			list, err := c.Approvals()
			if err != nil {
				return err
			}
			if len(list) == 0 {
				fmt.Println("no pending approvals")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "ID\tSESSION\tPROMPT\tREQUEST\tEXPIRES")
			for _, p := range list {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", p.ID, p.SessionLabel, p.Prompt, p.Request, time.Until(p.Expires).Round(time.Second))
			}
			return w.Flush()
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
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := dial()
			if err != nil {
				return err
			}
			return c.ResolveApproval(args[0], allow, session)
		},
	}
	cmd.Flags().BoolVarP(&session, "session", "s", false, "apply to identical requests for the rest of the session")
	return cmd
}

func sessionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "List agent sessions",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			c, err := dial()
			if err != nil {
				return err
			}
			list, err := c.Sessions()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "ID\tLABEL\tPROFILE\tCREATED")
			for _, s := range list {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.ID, s.Label, s.Profile, s.Created.Format(time.DateTime))
			}
			return w.Flush()
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "end ID",
		Short: "Revoke a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := dial()
			if err != nil {
				return err
			}
			return c.EndSession(args[0])
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
			got, err := app.Check(svc)
			if err != nil {
				return err
			}
			for _, p := range got.Profiles {
				fmt.Printf("profile %-14s %d http, %d ssh, unmatched=%s\n", p.Name, p.HTTP, p.SSH, p.Unmatched)
			}
			fmt.Printf("ok: %s\n", got.Path)
			return nil
		},
	}
}
