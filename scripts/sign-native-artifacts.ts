if (!process.env.NATIVE_ARTIFACT_SIGNING_KEY)
  throw new Error('Native artifact signing is not configured: set NATIVE_ARTIFACT_SIGNING_KEY.')
throw new Error(
  'Native artifact signing is not implemented; unsigned artifacts must not be claimed signed.'
)
