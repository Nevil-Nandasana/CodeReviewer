import * as vscode from 'vscode'

export function getConfig() {
  const cfg = vscode.workspace.getConfiguration('codereview-ai')
  return {
    apiUrl: cfg.get<string>('apiUrl') ?? 'http://localhost:8000',
    apiToken: cfg.get<string>('apiToken') ?? '',
  }
}
