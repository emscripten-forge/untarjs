# Release

In order to make a new release:
- Update the version in `package.json`
- Commit the change with the message "Release x.x.x" on the `main` branch
- Create a tag `git tag x.x.x`
- Push the new commit and the tag `git push https://github.com/emscripten-forge/untarjs main x.x.x`
- Build and publish `git clean -fdx && yarn && yarn run build && npm publish`
