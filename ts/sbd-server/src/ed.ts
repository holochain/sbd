// This ed25519 lib annoyingly needs a hash lib explicitly configured.
// Do that with their own recommended hash lib, and re-export that.

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
export { ed };
