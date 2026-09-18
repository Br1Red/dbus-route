# dbus-route

`dbus-route` is a small D-Bus session-bus proxy for Linux. It accepts one local
D-Bus connection and forwards each message to a bus selected by its destination
name. Messages that do not match a configured route continue to use the default
local session bus.

## Why it exists

Some Linux applications, such as Teams for Linux and Outlook for Linux, use the
Microsoft Identity Broker over D-Bus for authentication. This project makes it
possible to run those applications on a local machine while the Identity Broker
runs on another machine:

1. An SSH connection forwards the remote D-Bus socket to a local Unix socket.
2. `dbus-route` exposes another local Unix socket for applications to use.
3. Requests addressed to `com.microsoft.identity.broker1` are sent through the
	forwarded socket and therefore reach the remote broker.
4. All other D-Bus traffic is sent to the normal local session bus.

The applications remain local; only the selected D-Bus traffic is routed through
the remote host. `dbus-route` does not create the SSH tunnel and does not
implement Microsoft authentication itself.

## Features

- **Destination routing**: Route messages to different Unix-socket buses based on
	the D-Bus destination name
- **Local fallback**: Forward unmatched messages to a default session bus
- **Multiple routes**: Configure up to 100 alternate bus endpoints
- **UID-aware authentication**: Authenticate to each endpoint with an optional
	expected UID
- **D-Bus authentication**: Authenticate both incoming clients and outgoing bus
	connections
- **File descriptor passing**: Preserve ancillary file descriptors used by D-Bus
- **Concurrent clients**: Handle multiple clients with one worker thread per
	connection
- **Debug logging**: Print connection, routing and authentication details

## Building

```bash
make
```

This will compile `dbus-route` using gcc with optimization and pthread support.

To clean up build artifacts:

```bash
make clean
```

## Configuration

The command-line syntax is:

```text
dbus-route -l <listen-socket> -s <default-socket[@uid]> \
	[-r <destination>:<socket[@uid]>]... [-d]
```

Options:

- `-l, --listen PATH`: Unix socket exposed to local applications
- `-s, --session PATH[@UID]`: Default bus for messages that do not match a route
- `-r, --route DEST:PATH[@UID]`: Bus used for destinations beginning with `DEST`
- `-d, --debug`: Enable diagnostic logging
- `-h, --help`: Show command-line help

For example, this routes the Microsoft Identity Broker to a forwarded remote
bus while keeping all other traffic on the local session bus:

```bash
local_session_bus=${DBUS_SESSION_BUS_ADDRESS#*=}
local_socket_path=$(dirname "$local_session_bus")
remote_uid=$(ssh user@remote id -u)

dbus-route \
	-l "$local_socket_path/routed-bus" \
	-s "$local_session_bus" \
	-r "com.microsoft.identity.broker1:$local_socket_path/identity-bus@$remote_uid" \
	-d
```

`DBUS_SESSION_BUS_ADDRESS` normally has the form
`unix:path=/run/user/<uid>/bus`; the `unix:path=` prefix must be removed before
passing the socket path to `dbus-route`. The `@UID` suffix is optional and is
useful when the remote bus expects a specific peer UID.

Routes are matched in the order in which they are supplied, using a destination
prefix match. Put more specific routes before broader ones.

## SSH tunnel workflow

The companion script `identity-tunnel` in this repository automates the workflow used
for Teams for Linux and Outlook for Linux. It can be started with a remote SSH
target:

```bash
./identity-tunnel user@remote-host
```

Run it from the project directory after building with `make`, or invoke it by
its absolute path. If the local `dbus-route` binary is not present beside the
script, it falls back to the `dbus-route` executable found in `PATH`.

When started, the script:

- reads the local and remote session-bus socket paths;
- opens an SSH Unix-socket forward from the local machine to the remote bus;
- starts `dbus-route` with `com.microsoft.identity.broker1` routed remotely;
- creates per-user desktop-entry overrides for Teams for Linux, Outlook for
	Linux and Microsoft Edge so they use the routed bus;
- keeps the tunnel and proxy alive together and removes temporary sockets and
	desktop-entry overrides on exit.

The desktop entries prepend the project’s `bin` directory to `PATH`. The
included `bin/xdg-open` wrapper opens HTTP(S) links with Microsoft Edge and
delegates other paths to the system `/usr/bin/xdg-open`.

The script assumes that `ssh`, `sudo` and the listed applications are
installed. Build `dbus-route` in the project directory, or make it available
in `PATH`. The SSH key used by the script is `~/.ssh/identity_tunnel`. On the
remote host, add its public key to the target account’s `~/.ssh/authorized_keys`
with forwarding enabled but command execution restricted:

```text
restrict,port-forwarding,command="/usr/bin/echo do-not-send-commands" ssh-ed25519 AAAA... identity-tunnel
```

Replace `AAAA...` with the contents of `~/.ssh/identity_tunnel.pub`. The
`restrict` option disables shell, PTY, agent and X11 forwarding features;
`port-forwarding` explicitly re-enables only the forwarding needed by this
script. The forced command prevents the key from being used to execute remote
commands. The remote account must expose a usable `DBUS_SESSION_BUS_ADDRESS`,
and the SSH server must allow Unix-socket forwarding. The script also requires
permission to create and chown the forwarded Unix socket. Review the script
before use and adapt the remote host, SSH options and application list to your
environment.

## Architecture

- **Unix-socket proxy**: One listening socket accepts local D-Bus clients
- **Per-connection routing**: Each client connection is connected to the default
	bus and to every configured route endpoint
- **Destination inspection**: D-Bus headers are inspected to select the target
	bus without changing the application’s configured bus address
- **Ancillary FD support**: File descriptors are carried with messages in both
	directions
- **Epoll-based I/O**: Connections are multiplexed efficiently while worker
	threads handle clients independently

## Limitations

- Maximum 100 routes
- Maximum 64 concurrent clients
- Maximum 16 file descriptors per ancillary data message
- Maximum D-Bus message size of 128MB
- Destination matching uses prefixes and is case-sensitive
- The proxy must be running before applications connect to its socket
- The remote D-Bus socket must be reachable through SSH and usable by the
	configured UID

## License

This project is licensed under the GNU General Public License v3.0 or later.
See [LICENSE](LICENSE) for the license terms.
