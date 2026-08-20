#  Publishing Guide: How to Release STEALTHWALL to PyPI and npm

This document provides step-by-step instructions on how to build and publish STEALTHWALL to **PyPI (Python Package Index)** and **npm (Node Package Manager)**.

---

## 1.  How to Publish to PyPI (`pip install stealthwall`)

### Prerequisites:
- A PyPI account at [https://pypi.org](https://pypi.org)
- An API Token created under your PyPI Account Settings (`__token__`).
- `build` and `twine` installed:
  ```bash
  pip install --upgrade build twine
  ```

### Step 1: Verify `pyproject.toml` Version
Open `pyproject.toml` and confirm your release version:
```toml
[project]
name = "stealthwall"
version = "5.0.0"
```

### Step 2: Build Source and Wheel Distributions
Run the standard build tool from the project root:
```bash
python3 -m build
```
This generates two distribution files in the `dist/` directory:
- `dist/stealthwall-5.0.0.tar.gz` (Source Archive)
- `dist/stealthwall-5.0.0-py3-none-any.whl` (Binary Wheel)

### Step 3: Check Package Integrity
```bash
twine check dist/*
```

### Step 4: Upload to PyPI
```bash
twine upload dist/*
```
*Enter `__token__` as the username and your PyPI API token as the password.*

 Once uploaded, anyone in the world can install your package with:
```bash
pip install stealthwall
```

---

## 2.  How to Publish to npm (`npm install stealthwall`)

### Prerequisites:
- An npm account at [https://www.npmjs.com](https://www.npmjs.com)
- Log in to your npm CLI:
  ```bash
  npm login
  ```

### Step 1: Navigate to the Express Middleware Package
```bash
cd middleware/express
```

### Step 2: Verify `package.json`
Confirm the package details:
```json
{
  "name": "stealthwall",
  "version": "5.0.0",
  "main": "index.js"
}
```

### Step 3: Run Node Tests
```bash
node test/run_tests.js
```

### Step 4: Publish to npm
```bash
npm publish --access public
```

 Once published, anyone can install the package with:
```bash
npm install stealthwall
```

---

## 3.  Automated GitHub Actions CI/CD Workflow (Optional)

To publish automatically whenever you create a GitHub release tag (e.g. `v5.0.0`), create `.github/workflows/publish.yml`:

```yaml
name: Publish Releases to PyPI & npm

on:
  release:
    types: [published]

jobs:
  pypi-publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Build & Publish to PyPI
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
        run: |
          pip install build twine
          python -m build
          twine upload dist/*

  npm-publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'
      - name: Publish to npm
        working-directory: ./middleware/express
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: |
          npm publish --access public
```
