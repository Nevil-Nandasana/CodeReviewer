import * as vscode from 'vscode'
import axios from 'axios'
import { InlineDecorationProvider } from './inlineDecorations'
import { StatusBarManager } from './statusBar'
import { getConfig } from './config'

export class ReviewProvider {
  constructor(
    private decorations: InlineDecorationProvider,
    private statusBar: StatusBarManager,
  ) {}

  async reviewCurrentFile(editor: vscode.TextEditor, silent = false): Promise<void> {
    const { apiUrl, apiToken } = getConfig()
    if (!apiToken) {
      if (!silent) vscode.window.showWarningMessage('CodeReview AI: Set codereview-ai.apiToken in settings')
      return
    }

    const code = editor.document.getText()
    const filename = editor.document.fileName
    const language = editor.document.languageId

    if (!['python', 'javascript', 'typescript', 'java'].includes(language)) {
      if (!silent) vscode.window.showInformationMessage(`CodeReview AI: ${language} not supported yet`)
      return
    }

    this.statusBar.setLoading()
    if (!silent) vscode.window.showInformationMessage('CodeReview AI: Analyzing…')

    try {
      const diff = `--- a/${filename}\n+++ b/${filename}\n` +
        code.split('\n').map((l) => `+${l}`).join('\n')

      const resp = await axios.post(
        `${apiUrl}/api/v1/reviews/trigger`,
        { diff, language, filename },
        { headers: { Authorization: `Bearer ${apiToken}` }, timeout: 30_000 },
      )

      const comments = resp.data?.comments ?? []
      this.decorations.setComments(filename, comments)
      this.statusBar.update(comments.length)

      if (!silent) {
        const critical = comments.filter((c: any) => c.severity === 'CRITICAL').length
        const msg = comments.length === 0
          ? '✓ No issues found'
          : `Found ${comments.length} issues (${critical} critical)`
        vscode.window.showInformationMessage(`CodeReview AI: ${msg}`)
      }
    } catch (err: any) {
      this.statusBar.setError()
      if (!silent) {
        const msg = err.code === 'ECONNREFUSED' ? 'Cannot connect to CodeReviewer API' : err.message
        vscode.window.showErrorMessage(`CodeReview AI: ${msg}`)
      }
    }
  }
}
