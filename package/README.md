Creating a new release
----------------------

- Create a new release branch `git checkout -b release-v...`
- Update `CHANGES` with output of `./package/create-changes v-xx..`
- Edit `conserver/version.h`
- Run `./package/replicate-version-number`
- Double-check and merge release branch
- Run `./package/make-and-stage-release` to create distribution, pgp sign, tag release, and push to github

Requirements:

- autoconf
- githubrelease (pypi)
- gpg

Publishing a release
--------------------

- Use github to promote from draft or use the command output from `make-and-stage-release`
- Send announcement on mailing lists
