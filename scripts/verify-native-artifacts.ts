import { verifyNativeArtifacts } from './native-artifact-verifier.ts'

const directory = process.argv[2] ?? 'native-artifacts'
const releaseSha = process.argv[3]
if (!releaseSha) throw new Error('Usage: bun native:verify <directory> <checked-out-release-sha>')
await verifyNativeArtifacts(directory, releaseSha)
