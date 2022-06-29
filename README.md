# cfaccess-proxy

[![GitHub Super-Linter](https://github.com/j0sh3rs/cfaccess-proxy/workflows/Lint%20Code%20Base/badge.svg)](https://github.com/marketplace/actions/super-linter)

cfaccess-proxy is an HTTP proxy implemented to run transparently behind [Cloudflare
Access](https://teams.cloudflare.com/access/) and forward the email of the signed-in user to Grafana.
Running this small proxy between Cloudflare Access and Grafana instance allows you to
automatically sign in the authenticated user from Cloudflare Access into Grafana.

## 📥 Installation / Getting started

To accomplish this Grafana has to run in with the [Auth Proxy
Authentication](https://grafana.com/docs/grafana/latest/auth/auth-proxy/) mode enabled. This will
delegate the authentication to another component: Cloudflare Access + cfaccess-proxy in
this case.

A minimal `grafana.ini` config could look like this:

```ini
[users]
allow_sign_up = false
auto_assign_org = true
auto_assign_org_role = Editor

[auth.proxy]
enabled = true
header_name = X-WEBAUTH-USER
header_property = email
auto_sign_up = true
```

Running a Grafana docker container with the previous configuration can be done with the following command:

```shell
docker run --rm --name grafana -i -p 3000:3000 -v $(pwd)/grafana.ini:/etc/grafana/grafana.ini --name grafana grafana/grafana
```

In this case, the `header_property` set to `email` is important because the email is the claim
that we get from the JWT token provided by Cloudflare Access. `header_name` can be configured to any
desired value and will need to match the `FORWARDHEADER` environment variable passed into
cfaccess-proxy.

You can copy the template from [.env.template](.env.template) into your environment file and adjust
the required values. Now you can run the cfaccess-proxy container with the following command:

```
cp .env.template .env
docker run --rm -d --env-file $(pwd)/.env --name cloudflare-proxy -p 3001:3001 jorgelbg/cfaccess-proxy
```

This will start the proxy on the specified address and it will start to listen for incoming requests.
When a new HTTP request is received it will validate the JWT token, extract the `email` claim from
the token and forward to the specified host the header with the email address. Grafana will then
automatically signup/sign in (depending on the configuration) the user.

> Additional configuration on the Cloudflare Access is required to route your subdomain/DNS entry
> into the cfaccess-proxy instance. Grafana doesn't need to be accessible externally since
> all requests will go through the proxy.

## 👾 Known Issues

Since the authentication is no longer on the Grafana side, the logout action will not work as
expected. Although it will execute normally, you will find yourself logged in again. This happens
because the current user has not been logged out of Cloudflare Access.

## 🛠 Configuration

All the configuration options are passed to cloudflare-access-proxy as environment variables:

* `AUTHDOMAIN`: This is your cloudflare authentication domain. Normally in the form of `https://<your-own-domain>.cloudflareaccess.com`.
* `POLICYAUD`: Application Audience (AUD) Tag.
* `FORWARDUSERHEADER`: The header to be forwarded upstream to indicate which user is currently logged in.
* `FORWARDEMAILHEADER`: The header to be forwarded upstream to indicate the email of the user currently logged in.
* `FORWARDHOST`: URL where the Grafana instance (with `auth.proxy` enabled) is running.
* `ADDR`: Address where the cloudflare-access-proxy will listen for incoming connections.

## 👨🏻‍💻 Developing

```shell
git clone https://github.com/j0sh3rs/cfaccess-proxy
cd cfaccess-proxy/
make
```

This will build a binary placed in `bin/github.com/j0sh3rs/cfaccess-proxy` for your native platform.

If you want to build a new Docker image use the following command:

```shell
make docker
```

## 🤚🏻 Contributing

If you'd like to contribute, please fork the repository and use a feature
branch. Pull requests are warmly welcome.

## 🚀 Links

* The project logo is based on [Cloudflare icon](https://icons8.com/icons/set/cloudflare) by [Icons8](https://icons8.com).
