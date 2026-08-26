// npx semantic-release -e ./release.js

module.exports = {
  dryRun: false,
  plugins: [
    "@semantic-release/release-notes-generator",
    [ "@semantic-release/npm", {
        npmPublish: false } ],
    [ "@semantic-release/github", { addReleases: "top" } ]
  ]
};
