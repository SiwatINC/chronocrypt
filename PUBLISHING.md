# Publishing to npm

This guide explains how to publish `@siwats/chronocrypt` to npm.

## Prerequisites

1. **npm Account**: Create an account at [npmjs.com](https://www.npmjs.com/)
2. **npm CLI**: Ensure you have npm installed
3. **npm Login**: Run `npm login` and enter your credentials
4. **Scope Permission**: Ensure you have permission to publish to the `@siwats` scope

## Pre-Publish Checklist

Before publishing, verify:

- [ ] All tests pass: `bun test`
- [ ] Build succeeds: `bun run build`
- [ ] Version number is updated in `package.json`
- [ ] CHANGELOG is updated (if you maintain one)
- [ ] README is up to date
- [ ] All changes are committed to git
- [ ] Working on a clean git state

## Version Management

Update the version in `package.json` following [Semantic Versioning](https://semver.org/):

- **Patch** (1.0.x): Bug fixes, no API changes
  ```bash
  npm version patch
  ```

- **Minor** (1.x.0): New features, backward compatible
  ```bash
  npm version minor
  ```

- **Major** (x.0.0): Breaking changes
  ```bash
  npm version major
  ```

This command automatically:
- Updates `package.json`
- Creates a git commit
- Creates a git tag

## Publishing Steps

### 1. Build the Package

```bash
bun run build
```

This compiles TypeScript to JavaScript and generates type declarations in `dist/`.

### 2. Test the Package Locally (Optional)

Test the package before publishing:

```bash
# Create a test project
mkdir test-chronocrypt
cd test-chronocrypt
bun init -y

# Link your local package
cd /home/user/chronocrypt
bun link

# In test project
cd ../test-chronocrypt
bun link @siwats/chronocrypt

# Test it
cat > test.ts <<'EOF'
import { generateMasterKey } from '@siwats/chronocrypt';
const key = generateMasterKey();
console.log('Generated key:', key.length, 'bytes');
EOF

bun run test.ts
```

### 3. Dry Run

Preview what will be published:

```bash
npm publish --dry-run
```

This shows:
- Files that will be included
- Package size
- Any warnings or errors

### 4. Publish to npm

**For first-time publishing:**

```bash
npm publish --access public
```

The `--access public` flag is required for scoped packages to make them public.

**For subsequent publishes:**

```bash
npm publish
```

### 5. Verify Publication

Check that the package is available:

```bash
npm view @siwats/chronocrypt
```

Or visit: https://www.npmjs.com/package/@siwats/chronocrypt

### 6. Tag and Push to GitHub

```bash
git push origin main
git push origin --tags
```

## What Gets Published

The following files are included (configured in `package.json` `files` field):

- `dist/` - Compiled JavaScript and TypeScript declarations
- `README.md` - Package documentation
- `LICENSE` - MIT license file

The following are **excluded** (via `.npmignore`):

- Source files (`src/`)
- Tests (`tests/`)
- Examples (`examples/`)
- Configuration files
- Development dependencies

## Post-Publishing

### Create a GitHub Release

1. Go to your GitHub repository
2. Click "Releases" → "Create a new release"
3. Select the version tag (e.g., `v1.0.0`)
4. Add release notes describing changes
5. Publish release

### Update Documentation

- Update README if needed
- Update examples if API changed
- Create migration guide for breaking changes

## Publishing Beta Versions

For pre-release testing:

```bash
# Update version with beta tag
npm version 1.1.0-beta.1

# Publish with beta tag
npm publish --tag beta
```

Users can install beta versions:

```bash
bun add @siwats/chronocrypt@beta
```

## Unpublishing (Emergency Only)

You can only unpublish within 72 hours:

```bash
npm unpublish @siwats/chronocrypt@1.0.0
```

**Note**: Unpublishing is discouraged. Use deprecation instead:

```bash
npm deprecate @siwats/chronocrypt@1.0.0 "Security vulnerability, please upgrade to 1.0.1"
```

## Troubleshooting

### "You do not have permission to publish"

- Ensure you're logged in: `npm whoami`
- Check scope permissions for `@siwats`
- Use `--access public` for first publish

### "Version already exists"

- Bump the version number in `package.json`
- Or use `npm version patch/minor/major`

### "Build files missing"

- Run `bun run build` before publishing
- Check that `dist/` directory exists and contains files

### "Package size too large"

- Check `.npmignore` is properly configured
- Review what's included with `npm publish --dry-run`
- Ensure `node_modules/` is excluded

## Automation (CI/CD)

For automated publishing via GitHub Actions, create `.github/workflows/publish.yml`:

```yaml
name: Publish to npm

on:
  release:
    types: [created]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: oven-sh/setup-bun@v1

      - name: Install dependencies
        run: bun install

      - name: Run tests
        run: bun test

      - name: Build
        run: bun run build

      - name: Publish to npm
        run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

Add your npm token to GitHub Secrets as `NPM_TOKEN`.

## Best Practices

1. **Always test before publishing**: Run tests and build
2. **Use semantic versioning**: Follow semver strictly
3. **Keep a CHANGELOG**: Document all changes
4. **Don't publish breaking changes in patches**: Use major versions
5. **Deprecate instead of unpublish**: Except for serious issues
6. **Tag releases in git**: Makes tracking easier
7. **Monitor download stats**: Check npm for usage
8. **Respond to issues**: Be active in maintaining the package

## Support

- npm Documentation: https://docs.npmjs.com/
- Semantic Versioning: https://semver.org/
- GitHub Releases: https://docs.github.com/en/repositories/releasing-projects-on-github

## Quick Reference

```bash
# Complete publish workflow
bun test                    # Run tests
bun run build               # Build package
npm version patch           # Bump version
npm publish --dry-run       # Preview
npm publish --access public # Publish
git push origin main --tags # Push to GitHub
```
