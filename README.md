# CTFd++

## What is CTFd++?

CTFd++ is a fork of [CTFd](https://github.com/CTFd/CTFd), a Capture The Flag framework focusing on ease of use and customizability. It comes with everything you need to run a CTF, and it's easy to customize with themes.

This fork removes the MajorLeagueCyber integration and the update/telemetry check, inlines the challenge and flag types into the core (dropping the plugin system), and ships with a Caddy-based deployment.

![CTFd is a CTF in a can.](https://github.com/CTFd/CTFd/blob/master/CTFd/themes/core/static/img/scoreboard.png?raw=true)

## Features

- Create your own challenges, categories, hints, and flags from the Admin Interface
  - Dynamic Scoring Challenges
  - Unlockable challenge support
  - Challenge plugin architecture to create your own custom challenges
  - Static & Regex based flags
    - Custom flag plugins
  - Unlockable hints
  - File uploads to the server or an Amazon S3-compatible backend
  - Limit challenge attempts & hide challenges
  - Automatic bruteforce protection
- Individual and Team based competitions
  - Have users play on their own or form teams to play together
- Scoreboard with automatic tie resolution
  - Hide Scores from the public
  - Freeze Scores at a specific time
- Scoregraphs comparing the top 10 teams and team progress graphs
- Markdown content management system
- SMTP + Mailgun email support
  - Email confirmation support
  - Forgot password support
- Automatic competition starting and ending
- Team management, hiding, and banning
- Customize everything using the [plugin](https://docs.ctfd.io/docs/plugins/overview) and [theme](https://docs.ctfd.io/docs/themes/overview) interfaces
- Importing and Exporting of CTF data for archival
- And a lot more...

## Install

CTFd++ is built and run with [Docker Compose](https://docs.docker.com/compose/) —
the only supported deployment method. A [Caddy](https://caddyserver.com/) reverse
proxy is included by default and handles TLS automatically.

Configuration lives in [CTFdpp/config.ini](CTFdpp/config.ini) and can be overridden
with environment variables (see [docker-compose.yml](docker-compose.yml)).

**Deployment** (Caddy obtains a certificate for `SITE_ADDRESS`):

```
SITE_ADDRESS=ctf.example.com docker compose up
```

**Local testing** (plain HTTP, reachable at http://127.0.0.1:80):

```
docker compose -f docker-compose.yml -f docker-compose.local.yml up
```

Check out the [CTFd docs](https://docs.ctfd.io/) for [deployment options](https://docs.ctfd.io/docs/deployment/installation) and the [Getting Started](https://docs.ctfd.io/tutorials/getting-started/) guide

## Live Demo

https://demo.ctfd.io/

## Support

To get basic support, you can join the [MajorLeagueCyber Community](https://community.majorleaguecyber.org/): [![MajorLeagueCyber Discourse](https://img.shields.io/discourse/status?server=https%3A%2F%2Fcommunity.majorleaguecyber.org%2F)](https://community.majorleaguecyber.org/)

If you prefer commercial support or have a special project, feel free to [contact us](https://ctfd.io/contact/).

## Managed Hosting

Looking to use CTFd but don't want to deal with managing infrastructure? Check out [the CTFd website](https://ctfd.io/) for managed CTFd deployments.

## Credits

- Logo by [Laura Barbera](http://www.laurabb.com/)
- Theme by [Christopher Thompson](https://github.com/breadchris)
- Notification Sound by [Terrence Martin](https://soundcloud.com/tj-martin-composer)
