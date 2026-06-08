package main

import (
	"embed"
	"os"

	"Pulse/internal/pulse"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	releaseInstance, acquired, err := pulse.AcquireSingleInstance()
	if err != nil {
		println("Error:", err.Error())
		return
	}
	if !acquired {
		return
	}
	defer releaseInstance()

	// Create an instance of the app structure
	app := pulse.NewApp()
	pulse.StartTray(app)
	startHidden := hasStartHiddenArg(os.Args[1:])

	// Create application with options
	err = wails.Run(&options.App{
		Title:       "Pulse",
		Width:       1280,
		Height:      820,
		MinWidth:    1060,
		MinHeight:   680,
		Frameless:   true,
		StartHidden: startHidden,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 244, G: 246, B: 248, A: 1},
		DragAndDrop:      &options.DragAndDrop{EnableFileDrop: true},
		OnStartup:        app.Startup,
		OnShutdown:       app.Shutdown,
		OnBeforeClose:    app.BeforeClose,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}

func hasStartHiddenArg(args []string) bool {
	for _, arg := range args {
		if arg == "--start-hidden" || arg == "-start-hidden" {
			return true
		}
	}
	return false
}
