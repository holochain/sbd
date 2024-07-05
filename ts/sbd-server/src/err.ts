interface AddStatus {
  status: number;
}

type StatusError = Error & AddStatus;

/**
 * Adds a 'status' property to ts Error type.
 * If not specified will be set to 500.
 * Allows altering the http or ws error status for responses.
 * In the case of a websocket error, the http status code
 * will be added to 4000 for user-specified error codes.
 */
export function err(e: string, s?: number): StatusError {
  const out: any = new Error(e);
  out.status = s || 500;
  return out;
}
