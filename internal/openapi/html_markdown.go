package openapi

import (
	"html"
	"regexp"
	"strings"
)

// This file converts the constrained Markdown subset used in the document's
// prose (Info.Description, operation and tag descriptions) to HTML for the
// served /docs page. It is deliberately not a general Markdown renderer: it
// handles exactly the constructs the spec prose uses, and
// TestSpecProseRendersClean fails the build when the prose grows a construct
// this file does not understand — the alternative is that construct rendering
// as literal punctuation on the page.

var (
	codeSpanRe = regexp.MustCompile("`([^`]+)`")
	boldRe     = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	italicRe   = regexp.MustCompile(`\*([^*]+)\*`)
	linkRe     = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	tableSepRe = regexp.MustCompile(`^:?-+:?$`)
	headingRe  = regexp.MustCompile(`^(#{2,4}) (.*)$`)
)

// renderInline escapes s and applies inline markup: `code`, **bold**,
// *italic*, [text](url). Code spans are carved out first so markdown
// punctuation inside them stays literal.
func renderInline(s string) string {
	esc := html.EscapeString(s)
	var b strings.Builder
	last := 0
	for _, m := range codeSpanRe.FindAllStringSubmatchIndex(esc, -1) {
		b.WriteString(renderStyled(esc[last:m[0]]))
		b.WriteString("<code>")
		b.WriteString(esc[m[2]:m[3]])
		b.WriteString("</code>")
		last = m[1]
	}
	b.WriteString(renderStyled(esc[last:]))
	return b.String()
}

// renderStyled applies bold, italic, and links to already-escaped text. Bold
// runs before italic so `**x**` is consumed before the single-asterisk rule
// can see it.
func renderStyled(s string) string {
	s = boldRe.ReplaceAllString(s, "<strong>$1</strong>")
	s = italicRe.ReplaceAllString(s, "<em>$1</em>")
	s = linkRe.ReplaceAllString(s, `<a href="$2">$1</a>`)
	return s
}

// renderProse converts block-level markdown: headings (##–####, given the
// same anchor ids the Markdown rendering gets), fenced code, bullet lists,
// tables, and paragraphs. A lone `---` is a visual separator in the source
// and is dropped — the page's section styling already provides the break.
func renderProse(md string) string {
	var out, para []string

	flush := func() {
		if len(para) > 0 {
			out = append(out, "<p>"+renderInline(strings.Join(para, " "))+"</p>")
			para = nil
		}
	}

	lines := strings.Split(md, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		switch {
		case strings.HasPrefix(line, "```"):
			flush()
			var code []string
			for i++; i < len(lines) && !strings.HasPrefix(lines[i], "```"); i++ {
				code = append(code, lines[i])
			}
			out = append(out, "<pre><code>"+html.EscapeString(strings.Join(code, "\n"))+"</code></pre>")

		case headingRe.MatchString(line):
			flush()
			m := headingRe.FindStringSubmatch(line)
			tag := []string{"", "", "h2", "h3", "h4"}[len(m[1])]
			out = append(out, "<"+tag+` id="`+anchor(m[2])+`">`+renderInline(m[2])+"</"+tag+">")

		case strings.HasPrefix(line, "- "):
			flush()
			items := []string{"<ul>"}
			for ; i < len(lines) && strings.HasPrefix(lines[i], "- "); i++ {
				items = append(items, "<li>"+renderInline(lines[i][2:])+"</li>")
			}
			i--
			out = append(out, append(items, "</ul>")...)

		case strings.HasPrefix(line, "|"):
			flush()
			var rows []string
			for ; i < len(lines) && strings.HasPrefix(lines[i], "|"); i++ {
				rows = append(rows, lines[i])
			}
			i--
			out = append(out, renderTable(rows))

		case strings.TrimSpace(line) == "" || strings.TrimSpace(line) == "---":
			flush()

		default:
			para = append(para, strings.TrimSpace(line))
		}
	}
	flush()
	return strings.Join(out, "\n")
}

// renderTable converts a run of `| a | b |` lines. The first row is the
// header; a row whose every cell is dashes is the markdown separator and is
// dropped.
func renderTable(rows []string) string {
	var b strings.Builder
	b.WriteString(`<div class="tblwrap"><table>`)
	for r, row := range rows {
		cells := strings.Split(strings.Trim(row, "|"), "|")
		if r == 1 && allSeparators(cells) {
			continue
		}
		tag := "td"
		if r == 0 {
			tag = "th"
		}
		b.WriteString("<tr>")
		for _, cell := range cells {
			b.WriteString("<" + tag + ">" + renderInline(strings.TrimSpace(cell)) + "</" + tag + ">")
		}
		b.WriteString("</tr>")
	}
	b.WriteString("</table></div>")
	return b.String()
}

func allSeparators(cells []string) bool {
	for _, c := range cells {
		if !tableSepRe.MatchString(strings.TrimSpace(c)) {
			return false
		}
	}
	return true
}
