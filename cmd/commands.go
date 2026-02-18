package cmd

func init() {
	rootCmd.AddCommand(
		NewLoginCommand(),
		NewLogoutCommand(),
		NewConfigureCommand(),
		NewStatusCommand(),
		NewVersionCommand(),
		NewFavoritesCommand(),
	)
}
