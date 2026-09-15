// Package banner renders the temporary text banner. The final QYVORA logo
// system is designed separately; this banner is a dev placeholder explicitly
// marked TEMPORARY BRANDING and easy to replace via BANNER_TEXT.
package banner

import (
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"

	"github.com/QYVORA/qyvora-timbuktu/internal/version"
)

// DefaultText is a neutral, replaceable placeholder emblem. It must never
// pretend to be a final graphical identity.
const DefaultText = "TIMBUKTU"

// Text returns the banner text, overridable via the QYVORA_TIMBUKTU_BANNER
// environment variable for downstream branding pilots.
func Text() string {
	if v := os.Getenv("QYVORA_TIMBUKTU_BANNER"); v != "" {
		return v
	}
	return DefaultText
}

// Print writes the temporary banner (dev placeholder) to w with neutral
// styling. Colors are only used when writer is a TTY and NO_COLOR is unset.
func Print(w io.Writer, tty bool) {
	c := color.New(color.FgWhite, color.Bold)
	dim := color.New(color.FgWhite)
	if !tty {
		_, _ = fmt.Fprintf(w, "%s\n", Text())
		_, _ = fmt.Fprintf(w, "Cloud Security Assessment Framework v%s (TEMPORARY BRANDING)\n", version.Version)
		return
	}
	_, _ = c.Fprintf(w, "%s\n", Text())
	_, _ = dim.Fprintf(w, "Cloud Security Assessment Framework v%s\n", version.Version)
	_, _ = dim.Fprintf(w, "(TEMPORARY BRANDING — final logo system pending QYVORA design audit)\n")
}
