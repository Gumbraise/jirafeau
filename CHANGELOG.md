# Jirafeau's change log

## Note about upgrading

"in-place upgrade" refers to this general procedure:

1. Backup your Jirafeau installation!
2. Block access to Jirafeau
3. Checkout the new version with Git using the [tagged release](https://gitlab.com/jirafeau/Jirafeau/tags)
   * If you have installed Jirafeau just by uploading files on your server, you can download the desired version, overwrite/remove all files and chown/chmod files if needed. Keep a backup of your local configuration file tough.
4. With you browser, go to your Jirafeau root page
5. Follow the installation wizard, it should propose you the same data folder or even update automatically
6. Check your `/lib/config.local.php` and compare it with the `/lib/config.original.php` to see if new configuration items are available. If a new item is missing in your `config.local.php`, this may trigger some errors as Jirafeau may expect to have them.

## Version 4.7.x (not yet released)

- Favicon was missing in the `modern` theme
- ...

## Version 4.7.1

- Fixed another possibility to bypass the checks for [CVE-2022-30110](https://www.cve.org/CVERecord?id=CVE-2022-30110), [CVE-2024-12326](https://www.cve.org/CVERecord?id=CVE-2024-12326) and [CVE-2025-7066](https://www.cve.org/CVERecord?id=CVE-2025-7066) (prevent preview of SVG images and other critical files) by sending a manipulated HTTP request with a MIME type like "image". When doing the preview, the browser tries to automatically detect the MIME type resulting in detecting SVG and possibly executing JavaScript code. To prevent this, MIME sniffing is disabled. This issue has subsequently been reported as [CVE-2026-1466](https://www.cve.org/CVERecord?id=CVE-2026-1466).
- The default value of `max_upload_chunk_size_bytes` was set to `5000000`. Higher values could trigger a bug Chromium-based browsers on servers with HTTP/3 enabled, causing asynchronous uploads to fail.
- Docker image: Updated PHP to 8.3 and removed `mime-types.conf` from `lighttpd.conf`
- Upgrade from 4.7.0: in-place upgrade, you also should set `max_upload_chunk_size_bytes` to `5000000` in your `config.local.php`!

## Version 4.7.0

- Added feature for using shortened download links. This requires a web server that supports URL rewriting, like Apache with `mod_rewrite`.
- Added CSS class `tos` for addressing the link to the "Terms of Service" page
- Download stats introduced in version 4.6.0 were accidentally removed in version 4.6.1. This feature is now available again.
- Generated download passwords were not shown after the upload was completed
- Uploading a file using `script.php` with an upload password set always ended up in an "Error 2". This is fixed now.
- Upgrade from 4.6.3: in-place upgrade

New configuration items:
- `use_shortlinks` for enabling shortlinks

## Version 4.6.3

- Fixed the possibility to bypass the checks for [CVE-2022-30110](https://www.cve.org/CVERecord?id=CVE-2022-30110) and [CVE-2024-12326](https://www.cve.org/CVERecord?id=CVE-2024-12326) (prevent preview of SVG images and other critical files) by sending a manipulated HTTP request with a MIME type like "image/png,text/html". When doing the preview, the MIME type "text/html" takes precedence and you can execute for example JavaScript code. This issue has subsequently been reported as [CVE-2025-7066](https://www.cve.org/CVERecord?id=CVE-2025-7066).
- Compare password hashes using `hash_equals()`
- Upgrade from 4.6.2: in-place upgrade

## Version 4.6.2

- Allow to configure the language and the availabilities for files for a Docker container (issue [#20](https://gitlab.com/jirafeau/Jirafeau/-/issues/20))
- Added an example `docker-compose.yaml` file for configuring the Docker container
- Fixed an error occuring on some systems while building the Docker image (issue [#24](https://gitlab.com/jirafeau/Jirafeau/-/issues/24))
- Script upload was broken due to a missing `return` statement (issue [#23](https://gitlab.com/jirafeau/Jirafeau/-/issues/23))
- Upgrade from 4.6.1: in-place upgrade

## Version 4.6.1

- Removed the download button and the corresponding link for encrypted files from the admin interface
- Fixed an issue with sending the wrong filesize after decrypting an encrypted file
- Fixed the possibility to bypass the check for [CVE-2022-30110](https://www.cve.org/CVERecord?id=CVE-2022-30110) (prevent preview of SVG images) by sending a manipulated HTTP request with a MIME type like "image/svg+XML". This issue has subsequently been reported as [CVE-2024-12326](https://www.cve.org/CVERecord?id=CVE-2024-12326).
- We now provide Docker images for AMD64 and ARM64 systems
- Lots of code refactoring and cleanup
- Few more little fixes
- Typo and spelling mistakes
- Upgrade from 4.6.0: in-place upgrade

New configuration items:
- `one_time_download_preselected` for preselecting the checkbox for deleting the file after the first download

## Version 4.6.0

- New configuration options for allowing to require, check or generate file download passwords
- Re-implemented server side encryption using PHP's `Sodium` extension (the formerly used `mcrypt` extension is deprecated)
- Keep and show basic download stats
- Removed Lighttpd's `mod_usertrack` from Docker config
- Added `<meta name="viewport"…` to template header to support responsive themes
- Removed usage of deprecated `strftime()` function
- Few more little fixes
- Typo and spelling mistakes
- Upgrade from 4.5.0: in-place upgrade

New configuration items:
- `download_password_requirement`, `download_password_gen_len`, `download_password_gen_chars`, `download_password_policy` and `download_password_policy_regex` for configuring file download passwords
- `admin_ip` for limiting access to the admin interface to certain IP addresses
- `admin_http_auth_user` is now an array (the possibility to use a string is preserved for backward compatibility)

## Version 4.5.0

- Even more new translation, thanks a lot to all contributors!
- Support for automatic dark theme
- Fixed wobling admin buttons (light and dark default themes)
- Disable file deduplication by default
- Fix side effects of setting too high values in php configuration for async upload
- Add support for X-Sendfile
- Retry on more type of possible errors
- Move docker image to PHP 8.1 
- Print more error details in case of issue
- Few more little fixes
- IRC channel to discuss :)

New configuration items:
- `max_upload_chunk_size_bytes` option
- `dark_style` option
- Defaulting `file_hash` option from `md5` to `random`

## Version 4.4.0

- Add docker options
- Admin pannel can output informations for bug opening
- Fixes for PHP 8
- Fix autocomplete field for passwords
- Fix file previewing
- Disallow file preview for image/svg+xml files
- Expiry after a fortnight (2 weeks)
- Typo and spelling mistakes
- Upgrade from 4.3.0: in-place upgrade

New configuration items:
- `fortnight` value in `availabilities` array (default to `true`)

## Version 4.3.0

- Fix various docker errors
- Fix various upload errors
- Add composer (useful for CI)
- Code cleaning
- Add option 'store_uploader_ip' to avoid uploaders ip logging
- Upgrade from 4.2.0: in-place upgrade

New configuration items:
- `store_uploader_ip` (default to `true`)

## Version 4.2.0

- New file_hash option to eventually speed-up file identification process
- one_time_download is now optional
- Litespeed workaround for large files
- Admin interface can compute data folder size
- REUSE compliance test
- multiple docker features: mcrypt support, daily cleanup, unprivileged user
- Add upload password capability in script options
- Various bugfixes around retries and error management
- Automatically lower chunk size sent to server refusing large chunks
- Romanian lang support and other various lang support
- Upgrade from 4.1.1: in-place upgrade

## Version 4.1.1

- Fix lang sanity check
- Upgrade from 4.1.0: in-place upgrade

## Version 4.1.0

- Fix upload password and allowed ip (#201)
- Code refactorisation of IP checking
- Fix expiration dates
- Add better support for Accept-Language
- Cosmetic fixes
- More languages supported and language fixes
- Upgrade from 4.0.0: in-place upgrade

## Version 4.0.0

- Removed plain-text password support for admin auth (breaking change).
- Default folder sub-division to 8 characters (breaking change).
- New option `upload_ip_nopassword` to allow a list of IP to access Jirafeau without password
- Bugfix with LibreJS
- Other minor bug fixes
- More languages supported

### Upgrade from 3.4.1 to 4.0.0

You may have to change your administrator password in your config file as admin password are only stored using sha256 (SHA2).
To do so, edit `lib/config.local.php` and update `admin_password` option using `echo -n MyNewPassw0rd | sha256sum` command.

Subfolder division changed in Jirafeau storage. You can either start from a fresh `var-` folder or you need to migrate your data.

In order to migrate your existing data:
1. Be sure to have a working backup of your Jirafeau instance and/or the rest of your hosting before any operation
2. Go to `var-` folder
3. Be sure you have read and write permissions on files and folders with your current user
4. Run the following commands:
```bash
# Migrate files folder
find files -type f ! -name "*_count" | while read f; do bn="$(basename "$f")"; dst="files/${bn:0:8}/${bn:8:8}/${bn:16:8}/${bn:24:8}/"; mkdir -p "$dst"; mv "$f" "$dst" ; mv "${f}_count" "$dst"; done; find files -maxdepth 1 -type d -iname "?" -exec rm -rf {} \;
# Migrate links folder
find links -type f | while read link; do bn="$(basename "$link")"; mkdir "links/$bn"; mv "$link" "links/$bn/"; done; find links -maxdepth 1 -type d -iname "?" -exec rm -rf {} \;
```

## Version 3.4.1

- Security fixes, thanks [Bishopfox Team](https://www.bishopfox.com/)
- Translation fixes
- Docker fix
- Advertise JavaScript license for LibreJS compatibility
- other minor fixes
- Upgrade from 3.4.0: in-place upgrade

## Version 3.4.0

- Add encryption support in bash script
- Refactoring of lang system for simpler management
- Removed installation step asking for language
- Merged weblate contributions
- Fixed some spelling issues
- Upgrade from 3.3.0 : in-place upgrade

## Version 3.3.0

- Added Docker Support
- Added a copy button next to links to copy URLs in clipboard
- Now use a delete page to confirm file deletion (#136)
- Fixed object ProgressEvent Error (#127)
- Added configuration tips for web servers
- More translations
- Style fixes
- Removed useless alias API support (some old toy)
- Upgrade from 3.2.1 : in-place upgrade

## Version 3.2.1

- fix download view after an upload
- Upgrade from 3.2.0 : in-place upgrade

## Version 3.2.0

- Update translations from Update translations from weblate
- Better style
- Fix regression on admin password setting
- Upgrade from 3.1.0 : in-place upgrade

## Version 3.1.0

- Fix regression on user authentication (see #113)
- Some cosmetic change
- Upgrade from 3.0.0 : in-place upgrade

## Version 3.0.0

- Remove XHTML doctype, support HTML5 only → breaking change for older browsers
- Remove redundant code
- Remove baseurl usage and set absolute links instead, which for example fixes SSL issues
- Extend contribution guide
- Switch to PSR-2 code style (fix line endings, indentations, whitespaces, etc)
- Declare system requirements
- Catch API errors in upload form
- Allow clients to upload files depending on IP or password
- Set UTC as timezone to prevent date/time issues
- Show readable date & time information
- Fix UI glitches in admin panel and upload form
- Upgrade from 2.0.0 : in-place upgrade

## Version 2.0.0

- Various documentation improvements
- Simplify automatic generation of local configuration file
- Set a custom title
- Bash Script: Enhanced help, show version, return link to web view as well
- »Terms of Service« refactored - Enable admin to overwrite the ToS, without changing existing source code → breaking, see upgrade notes

### Upgrade from version 1.2.0 to 2.0.0

The "Terms of Service" text file changed.
To reuse a custom version of your ToS, move your ```/tos_text.php``` file to ```/lib/tos.local.txt``` and remove all HTML und PHP Tags, leaving a regular text file.

## Version 1.2.0

- Link on API page to generate bash script
- More informative error codes for API
- Security Fix: Prevent authentication bypass for admin interface
- CLI script to remove expired files automatically with a cron job
- SHA-256 hash the admin password
- New theme "elegantish"
- Fix for JavaScript MIME-Type, prevents blocking the resource on some servers
- Show download link for a file in admin interface
- Default time for expiration (set to 'month' by default)
- New expiration time: 'quarter'
- A lot of translation contributions
- Code cleanups
- Upgrade from 1.1: in-place upgrade

## Version 1.1

- New skins
- Add optional server side encryption
- Unlimited file size upload using HTML5 file API
- Show speed and estimated time during upload
- A lot of fixes
- A lot of new languages
- Small API to upload files
- Limit access to Jirafeau using IP, mask, passwords
- Manage (some) proxy headers
- Configure your maximal upload size
- Configure file's lifetime durations
- Preview URL
- Get Jirafeau's version in admin interface

### Upgrade from version 1.0 to 1.1

- Download URL changed. Add a rewrite rule in your web server configuration to rename ```file.php``` to ```f.php``` to make older, still existing links work again-
- The default theme changed. Optionally change the theme in ```lib/config.local.php``` to "courgette"

## Version 1.0

The very first version of Jirafeau after the fork of Jyraphe.

- Security fix
- Keep uploader's ip
- Delete link for each upload
- No more clear text password storage
- Simple language support
- Add an admin interface
- New Design
- Add term of use
- New path system to manage large number of files
- New option to show a page at download time
- Add option to activate or not preview mode
