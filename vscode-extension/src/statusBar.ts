import * as vscode from 'vscode'

export class StatusBarManager implements vscode.Disposable {
  private item: vscode.StatusBarItem

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100)
    this.item.command = 'codereview-ai.reviewFile'
    this.item.text = '$(shield) CodeReview AI'
    this.item.tooltip = 'Click to review current file'
    this.item.show()
  }

  update(issueCount: number) {
    if (issueCount === 0) {
      this.item.text = '$(shield) No issues'
      this.item.backgroundColor = undefined
      this.item.color = new vscode.ThemeColor('statusBarItem.prominentForeground')
    } else {
      this.item.text = `$(shield) ${issueCount} issue${issueCount > 1 ? 's' : ''}`
      this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground')
      this.item.color = undefined
    }
  }

  setLoading() {
    this.item.text = '$(sync~spin) Reviewing…'
    this.item.backgroundColor = undefined
  }

  setError() {
    this.item.text = '$(shield) Review failed'
    this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground')
  }

  dispose() { this.item.dispose() }
}
