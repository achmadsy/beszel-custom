package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`CREATE TABLE IF NOT EXISTS security_known_ips (system TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE, network TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', PRIMARY KEY(system,network))`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery(`DROP TABLE IF EXISTS security_known_ips`).Execute()
		return err
	})
}
