# Publishing this project to GitHub

The repository lives here: <https://github.com/Pandu49251/nexus-system-doctor>

## From a machine with the GitHub CLI

```bash
gh auth login                 # once
./push-to-github.sh           # creates the repo (public) and pushes
./push-to-github.sh --private # or private
```

## Manually

1. Create an empty repository at <https://github.com/new>
   - **Name:** `nexus-system-doctor`
   - **Public** (or private, your choice)
   - Do **not** tick "Add a README file", `.gitignore` or licence — the project
     already has all three, and initialising would cause a merge conflict.

2. Push from this directory:

   ```bash
   git remote add origin https://github.com/Pandu49251/nexus-system-doctor.git
   git push -u origin main --tags
   ```

3. Publish the release with the installer attached:

   ```bash
   ./packaging/build-deb.sh
   gh release create v1.0.0 dist/*.deb --generate-notes
   ```

## After the first push

- **Actions** tab → the test workflow runs 67 tests and uploads the `.deb`.
- **Settings → Pages** → *Deploy from branch* → branch `main`, folder
  `/docs/site` → documentation at
  `https://pandu49251.github.io/nexus-system-doctor/`.
- The README badge and clone URL already point at this repository.

## Rebuilding the documentation site

```bash
python3 tools/build_docs_site.py            # writes docs/site/
python3 tools/build_docs_site.py --serve    # ... and serve it on :8000
```
