# Contributing

Hi,

this document is made for newcomers in Jirafeau who are digging into the code.

If you have further questions, then just ask for help 🤓.

## General principle

Jirafeau is made in the [KISS](http://en.wikipedia.org/wiki/KISS_principle) way (Keep It Simple, Stupid).

It is meant to be a simple filehosting service, simple to use, simple to install, simple to maintain.

This project won't evolve to a file manager and will focus to keep a very few dependencies.

So things like a markdown parser for the ToS or E-Mail tasks would be useful for sure, but were [rejected](https://gitlab.com/mojo42/Jirafeau/issues/37#note_1191566) long ago since they would add a lot of dependencies and makes the project more complex.

## Structure

Here is a little explanation of Jirafeau's structure in a simplified
view only to show the most important files and their role.

```
.
├── admin.php : administration interface to manage links and files
├── docker : folder containing some configuration files to run Jirafeau in docker
├── f.php : permits to download files or show the download page
├── index.php : provides a web interface to interact with API
├── script.php : API interface (all file actions happen here - upload, deletion, etc)
├── install.php : installation script
├── tos.php : "Terms of Service" page
├── lib
│   ├── config.original.php : default parameters
│   ├── config.local.php : the users parameters (auto generated, not versioned)
│   ├── functions_*.js : JavaScript functions for index.php (AJAX etc)
│   ├── functions.php : core functions and tools of Jirafeau
│   ├── tos.original.txt : default text show on the ToS page
│   ├── tos.local.txt : a users alternative text show on the ToS page (not versioned)
│   ├── settings.php : core settings of Jirafeau, includes the configuration params automatically
│   ├── locales : language folder, contains all language files
│   └── template
│       ├── footer.php : footer with links to source and ToS for all HTML views
│       └── header.php : header with logo and title for all HTML views
├── media : folder containing all skins
└── var-xxxxxxx : the users folder containing all data (auto generated, not versioned)
    ├── async : chunks of uploaded files (not successful yet) 
    ├── files : all files that have been uploaded successfully
    │   ├── [hashed file name] : the original file
    │   └── [hashed file name]_count : count many links to this file exist
    └── links : all links, including metadata, pointing to files
        └── [link] : the link file, includes which original file should be used and some meta data like creation date, expiration time
```

## Translations

Translation may be added via [Jirafeau's Weblate](https://hosted.weblate.org/projects/jirafeau/master/).

## Coding style

- This project follows the [PSR-2](http://www.php-fig.org/psr/psr-2/) Coding Style
- Files must be in UTF-8 without BOM and use Unix Line Endings (LF)

## Branches

* ```master``` = latest release, e.g. 2.0.1
* ```next-release``` = development branch - all new features are merged into this branch until the next version is released. So use this branch as base while developing new features or bugfixes.
* ```test``` = sandbox branch to test new features or merge requests, or run integration tests. The content of this branch may change at any time.

## Merge Requests

Please create one branch for each feature and send one merge request for each branch. 

Don't squash several changes or commits into one merge request as this is hard to review.

Please use ```next-release``` as base branch and send your merge request to this branch (not ```master```).

Quick walkthrough:

* Create ticket for new feature
* Fork the original repository, clone the own repository, add the original repository as upstream
* Checkout »next-release« branch ```git checkout next-release```
* Create a new branch on top of that one, e.g. »some-feature« ```git checkout -b some-feature```
* Make your change
* You may check if the project is still [REUSE Compliant](https://reuse.software/) by running `docker run -v $(pwd):/code --rm fsfe/reuse /bin/sh -c "cd /code && reuse lint"`
* Commit changes → push → send merge request ```git add -A; git commit; git push``` MR via GitLab (link shown in console)
* Feature is reviewed
  * MR accepted: Reviewer checks out »next-release« branch and cherry-picks the commit ```git checkout next-release; git cherry-pick be4369641; git push```
  * MR declined: Reviewer add some notes, Developer rebases his branch, adds neccessary changes, force pushes the branch, ask a reviewer to review the changes in the merge request ticket (as Gitlab recognizes them automatically) ```git checkout some-feature; git rebase upstream/next-release``` …[add changes]… ```git add -A, git commit --amend; git push -f```

## New Releases

* Fetch weblate and rebase and import translations
* If the release is not done for security purposes: create a new issue and freeze next-release branch for at least week.
* Compare the [»next-release« branch to »master«](https://gitlab.com/jirafeau/Jirafeau/compare/master...next-release)
* Add a list of noteworthy features and bugfixes to `CHANGELOG.md`
* Add eventual upgrade procedure to `CHANGELOG.md`. Make sure to list all new configuration items.
* Build and test docker image
* Change the version, using [semantic versioning](http://semver.org/), in ```settings.php```
* Merge »next-release« branch to »master«
* Tag the »master« with the new version
* Push branch and tag
* Push new docker image
* Update the demo page
* Dance a little
