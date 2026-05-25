import * as vscode from 'vscode'

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

const SEVERITY_COLORS: Record<Severity, { border: string; bg: string }> = {
  CRITICAL: { border: 'rgba(239,68,68,0.9)', bg: 'rgba(239,68,68,0.05)' },
  HIGH:     { border: 'rgba(249,115,22,0.9)', bg: 'rgba(249,115,22,0.05)' },
  MEDIUM:   { border: 'rgba(234,179,8,0.9)',  bg: 'rgba(234,179,8,0.05)'  },
  LOW:      { border: 'rgba(59,130,246,0.9)', bg: 'rgba(59,130,246,0.05)' },
  INFO:     { border: 'rgba(139,92,246,0.9)', bg: 'rgba(139,92,246,0.05)' },
}

interface CommentData {
  line: number
  severity: Severity
  title: string
  explanation: string
  suggestion?: string
  owasp?: string
}

export class InlineDecorationProvider {
  private decorationTypes: Map<Severity, vscode.TextEditorDecorationType> = new Map()
  private fileComments: Map<string, CommentData[]> = new Map()

  constructor() {
    for (const [sev, colors] of Object.entries(SEVERITY_COLORS) as [Severity, typeof SEVERITY_COLORS[Severity]][]) {
      this.decorationTypes.set(
        sev,
        vscode.window.createTextEditorDecorationType({
          borderWidth: '0 0 2px 0',
          borderStyle: 'solid',
          borderColor: colors.border,
          backgroundColor: colors.bg,
          isWholeLine: true,
        })
      )
    }
  }

  setComments(filePath: string, comments: CommentData[]) {
    this.fileComments.set(filePath, comments)
    const editor = vscode.window.activeTextEditor
    if (editor && editor.document.uri.fsPath === filePath) {
      this.applyToEditor(editor)
    }
  }

  applyToEditor(editor: vscode.TextEditor) {
    const filePath = editor.document.uri.fsPath
    const comments = this.fileComments.get(filePath) ?? []

    // Clear all decorations first
    for (const dt of this.decorationTypes.values()) {
      editor.setDecorations(dt, [])
    }

    // Group by severity
    const bySeverity = new Map<Severity, vscode.DecorationOptions[]>()
    for (const comment of comments) {
      if (!bySeverity.has(comment.severity)) bySeverity.set(comment.severity, [])
      const lineIndex = Math.max(0, comment.line - 1)
      const range = editor.document.lineAt(Math.min(lineIndex, editor.document.lineCount - 1)).range

      const markdown = new vscode.MarkdownString(
        `**${comment.severity}: ${comment.title}**\n\n${comment.explanation}` +
        (comment.suggestion ? `\n\n**Fix:**\n\`\`\`python\n${comment.suggestion}\n\`\`\`` : '') +
        (comment.owasp ? `\n\n*${comment.owasp}*` : ''),
        true
      )
      markdown.isTrusted = true

      bySeverity.get(comment.severity)!.push({ range, hoverMessage: markdown })
    }

    // Apply decorations per severity
    for (const [sev, decorations] of bySeverity) {
      const dt = this.decorationTypes.get(sev)
      if (dt) editor.setDecorations(dt, decorations)
    }
  }

  clearAll() {
    this.fileComments.clear()
    for (const editor of vscode.window.visibleTextEditors) {
      for (const dt of this.decorationTypes.values()) {
        editor.setDecorations(dt, [])
      }
    }
  }

  getCommentCount(filePath: string): number {
    return this.fileComments.get(filePath)?.length ?? 0
  }

  dispose() {
    for (const dt of this.decorationTypes.values()) dt.dispose()
    this.decorationTypes.clear()
  }
}
