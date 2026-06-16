package cmd

import (
	"errors"
	"fmt"
)

// Users dispatches `authio users <subcommand>`.
func Users(args []string) error {
	if len(args) == 0 {
		return errors.New(usersUsage())
	}
	switch args[0] {
	case "import":
		return UsersImport(args[1:])
	case "help", "--help", "-h":
		fmt.Println(usersUsage())
		return nil
	}
	return fmt.Errorf("unknown users subcommand %q (try `authio users help`)", args[0])
}

func usersUsage() string {
	return `usage: authio users <subcommand>

SUBCOMMANDS
  import    Import users from a CSV or JSON file (custom auth migrations)

FLAGS (import)
  --file <path>              required; CSV or JSON export
  --org <org_id>             optional org membership for every imported user
  --project <project_id>     override project (uses profile default otherwise)
  --email-verified           mark imported users as email-verified
  --dry-run                  parse and count without POSTing
  --duplicate-policy <p>     skip (default) or update existing users by email
  --format <csv|json|auto>   file format (default: auto from extension)
  --profile <name>           credentials profile (default: active profile)

CSV columns (header row required):
  email (required), name, external_id, role, org

JSON: array of { email, name?, external_id?, role?, org? }

See https://docs.authio.com/quickstart/user-import`
}
