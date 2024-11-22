# Jirafeau's Docker image

## Run Jirafeau through a pre-made Docker image

Jirafeau is a small PHP application so running it inside a Docker container is pretty straightforward. Container images are built for AMD64 and ARM64 systems and can be downloaded from our registry at `registry.gitlab.com`.

```shell
docker pull registry.gitlab.com/jirafeau/jirafeau:latest
docker run -it --rm -p 8080:80 registry.gitlab.com/jirafeau/jirafeau:latest
```

Then connect on [localhost:8080](http://localhost:8080/).
The admin console is located on `/admin.php`, check console output to get auto-generated admin password.

## Build your own Jirafeau docker image

```shell
git clone https://gitlab.com/jirafeau/Jirafeau.git
cd Jirafeau
docker build -t your/jirafeau:latest .
```

## Security

You may be interested in running Jirafeau on port 80:

```shell
docker run -d -p 80:80 --sysctl net.ipv4.ip_unprivileged_port_start=80 registry.gitlab.com/jirafeau/jirafeau
```

Note that Jirafeau image does not provide any SSL/TLS. You may be interested in using [docker compose](https://docs.docker.com/compose/) combined with [Let's Encrypt](https://letsencrypt.org/).

## Options

Jirafeau's docker image accepts some options through environment variables to ease its configuration.
More details about options in `lib/config.original.php`.

Available options:
- `ADMIN_PASSWORD`: setup a specific admin password. If not set, a random password will be generated.
- `ADMIN_IP`: set one or more ip allowed to access admin interface (separated by comma).
- `WEB_ROOT`: setup a specific domain to point at when generating links (e.g. 'jirafeau.mydomain.com/').
- `VAR_ROOT`: setup a specific path where to place files. default: '/data'.
- `FILE_HASH`: can be set to `md5`, `partial_md5` or `random` (default).
- `PREVIEW`: set to 1 or 0 to enable or disable preview.
- `TITLE`: set Jirafeau instance title.
- `ORGANISATION`: set organisation (in ToS).
- `CONTACTPERSON`: set contact person (in ToS).
- `STYLE`: apply a specific style from the media folder.
- `DARK_STYLE`: apply a specific style for browsers in dark mode.
- `AVAILABILITY_DEFAULT`: setup which availability shows by default.
- `ONE_TIME_DOWNLOAD`: set to 1 or 0 to enable or disable one time downloads.
- `ONE_TIME_DOWNLOAD_PRESELECTED`: set to 1 or 0 to preselect the checkbox for one time downloads.
- `ENABLE_CRYPT`: set to 1 or 0 to enable or disable server side encryption.
- `DEBUG`: set to 1 or 0 to enable or disable debug mode.
- `MAXIMAL_UPLOAD_SIZE`: maximal file size allowed (expressed in MB).
- `UPLOAD_PASSWORD`: set one or more passwords to access Jirafeau (separated by comma).
- `UPLOAD_IP`: set one or more ip allowed to upload files (separated by comma).
- `UPLOAD_IP_NO_PASSWORD`: set one or more ip allowed to upload files without password (separated by comma).
- `PROXY_IP`: set one or more proxy ip (separated by comma).
- `STORE_UPLOADER_IP`: set to 1 or 0 to enable or disable keeping sender's IP with the _link_ file.
- `DOWNLOAD_PASSWORD_REQUIREMENT`: set to 'optional' (default), 'required' or 'generated' to make a password for downloading optional, required or generated
- `DOWNLOAD_PASSWORD_GEN_LEN`: set length of generated download passwords
- `DOWNLOAD_PASSWORD_GEN_CHARS`: set characters used for generated download passwords
- `DOWNLOAD_PASSWORD_POLICY`: set to 'regex' to use a regular expression to check user provided download passwords for complexity constraints
- `DOWNLOAD_PASSWORD_POLICY_REGEX`: regex to check against if password policy is set to regex

Example:

```shell
docker run -it -p 8080:80 --rm -e ADMIN_PASSWORD='p4ssw0rd' -e WEB_ROOT='jirafeau.mydomain.com/' -e UPLOAD_PASSWORD='foo,bar' -e PREVIEW=0  registry.gitlab.com/jirafeau/jirafeau:latest
```

## Data storage

Files and links are stored in `/data` by default. Subfolders are automatically created with needed permissions at creation if needed.
Note that configuration is not stored in /data.

Example of using a dedicated volume to store Jirafeau data separately from the container:

```shell
docker volume create jirafeau_data
docker run -it --rm -p 8080:80 --mount source=jirafeau_data,target=/data registry.gitlab.com/jirafeau/jirafeau:latest
```

It is also possible to put Jirafeau data into an already existing directory outside the container:

```shell
mkdir /tmp/jirafeau_data
docker run -it --rm -p 8080:80 -v /tmp/jirafeau_data:/data registry.gitlab.com/jirafeau/jirafeau:latest
```

Please note that the files and directories created in the directory outside the container will probably be owned by UID 100.

## Few notes

- `var-...` folder where lives all uploaded data is protected from direct access
- Image has been made using [Alpine Linux](https://alpinelinux.org/) with [lighttpd](https://www.lighttpd.net/) which makes the container very light and start very quickly
