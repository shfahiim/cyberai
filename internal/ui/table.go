package ui

import (
	"io"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

// TableColumnAlign controls per-column alignment in RenderTable.
type TableColumnAlign int

const (
	AlignLeft TableColumnAlign = iota
	AlignRight
	AlignCenter
)

// TableOptions configures RenderTable.
type TableOptions struct {
	// ColumnAligns, if non-nil, sets per-column alignment. Default is left.
	ColumnAligns []TableColumnAlign
	// NoHeader suppresses the header row.
	NoHeader bool
}

// RenderTable writes headers and rows to w as a modern, minimal column-aligned
// list (no box drawing). Cell text is passed through verbatim — do not put
// ANSI codes in cells.
func RenderTable(w io.Writer, headers []string, rows [][]string, opts ...TableOptions) {
	var o TableOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	if w == nil {
		w = os.Stdout
	}

	// Disable all borders and separator lines for a clean column list look.
	// The default Blueprint renderer draws ┌─┐ │ ├─┤ etc.; we want none of
	// that.
	rendition := tw.Rendition{
		Borders: tw.Border{
			Left:   tw.Off,
			Right:  tw.Off,
			Top:    tw.Off,
			Bottom: tw.Off,
		},
		Settings: tw.Settings{
			Lines: tw.Lines{
				ShowTop:        tw.Off,
				ShowBottom:     tw.Off,
				ShowHeaderLine: tw.Off,
				ShowFooterLine: tw.Off,
			},
			Separators: tw.Separators{
				ShowHeader:     tw.Off,
				ShowFooter:     tw.Off,
				BetweenRows:    tw.Off,
				BetweenColumns: tw.Off,
			},
		},
		Symbols: tw.NewSymbols(tw.StyleNone),
	}

	var tableOpts []tablewriter.Option
	tableOpts = append(tableOpts, tablewriter.WithRendition(rendition))
	if !o.NoHeader {
		tableOpts = append(tableOpts, tablewriter.WithHeader(headers))
	}
	if len(o.ColumnAligns) > 0 {
		aligns := make(tw.Alignment, len(o.ColumnAligns))
		for i, a := range o.ColumnAligns {
			switch a {
			case AlignRight:
				aligns[i] = tw.AlignRight
			case AlignCenter:
				aligns[i] = tw.AlignCenter
			default:
				aligns[i] = tw.AlignLeft
			}
		}
		tableOpts = append(tableOpts, tablewriter.WithAlignment(aligns))
	}

	tw := tablewriter.NewTable(w, tableOpts...)
	for _, r := range rows {
		_ = tw.Append(r)
	}
	_ = tw.Render()
}

// RenderSimpleTable is a convenience for the common case of a header + body.
// Equivalent to RenderTable(w, headers, rows).
func RenderSimpleTable(w io.Writer, headers []string, rows [][]string) {
	RenderTable(w, headers, rows)
}
