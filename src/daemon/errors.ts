/**
 * Error codes the daemon RPC surface reports deliberately. They mirror the
 * subset of `RpcFailure['error']['code']` values that used to be inferred from
 * message substrings; carrying the code explicitly keeps internal errors that
 * merely mention 'limit' or 'closed' from being misclassified.
 */
export type DaemonErrorCode = 'authorization' | 'limit' | 'not_found' | 'session_closed'

export class DaemonError extends Error {
  constructor(
    message: string,
    readonly code: DaemonErrorCode
  ) {
    super(message)
    this.name = 'DaemonError'
  }
}
