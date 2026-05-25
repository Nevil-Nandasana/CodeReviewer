import * as vscode from 'vscode'
import { InlineDecorationProvider } from './inlineDecorations'
import { StatusBarManager } from './statusBar'
import { ReviewProvider } from './reviewProvider'

let decorationProvider: InlineDecorationProvider
let statusBar: StatusBarManager

export function activate(context: vscode.ExtensionContext) {
  console.log('CodeReview AI extension activated')

  decorationProvider = new InlineDecorationProvider()
  statusBar = new StatusBarManager()
  const reviewProvider = new ReviewProvider(decorationProvider, statusBar)

  // Commands
  const reviewCmd = vscode.commands.registerCommand('codereview-ai.reviewFile', async () => {
    const editor = vscode.window.activeTextEditor
    if (!editor) {
      vscode.window.showWarningMessage('No active file to review')
      return
    }
    await reviewProvider.reviewCurrentFile(editor)
  })

  const clearCmd = vscode.commands.registerCommand('codereview-ai.clearDecorations', () => {
    decorationProvider.clearAll()
    statusBar.update(0)
    vscode.window.showInformationMessage('CodeReview AI: Decorations cleared')
  })

  // Auto-review on file save
  const saveListener = vscode.workspace.onDidSaveTextDocument(async (doc) => {
    const editor = vscode.window.visibleTextEditors.find((e) => e.document === doc)
    if (editor) await reviewProvider.reviewCurrentFile(editor, true)
  })

  // Update decorations when switching files
  const switchListener = vscode.window.onDidChangeActiveTextEditor((editor) => {
    if (editor) decorationProvider.applyToEditor(editor)
  })

  context.subscriptions.push(reviewCmd, clearCmd, saveListener, switchListener, statusBar)
}

export function deactivate() {
  decorationProvider?.clearAll()
  statusBar?.dispose()
}
