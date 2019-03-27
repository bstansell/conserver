Creating a new release
----------------------

- Create a new release branch `git checkout -b release-vx.y.z`
- Edit `conserver/version.h`
- Update `CHANGES` with output of `./package/create-changes vx.y.z..`
- Double-check and merge release branch
- Run `GITHUB_TOKEN=xxxx ./package/make-and-stage-release` to tag release, create distribution, pgp sign, and push to github

Requirements:

- autoconf
- githubrelease (pypi)
- gpg

Publishing a release
--------------------

- Use github to promote from draft or use the command output from `make-and-stage-release`
- Send announcement on mailing lists
