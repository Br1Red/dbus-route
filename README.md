# dbus-route

A D-Bus message router that forwards D-Bus connections between different socket paths. This utility allows routing D-Bus traffic with support for authentication, per-route UID configuration, and file descriptor passing.

## Features

- **Message Routing**: Route D-Bus messages between multiple socket endpoints
- **Per-Route Configuration**: Define different socket paths and UID restrictions for each route
- **Ancillary Data Support**: Handle file descriptor passing through D-Bus messages
- **Efficient I/O**: Uses epoll for scalable socket multiplexing
- **Authentication**: Support for UID-based access control
- **Debug Mode**: Verbose logging for troubleshooting
- **Multi-threaded**: Handles concurrent connections

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

The application supports the following route configuration options:

- **Destination**: Target D-Bus destination name
- **Socket Path**: Unix socket path for the route
- **UID**: Optional UID restriction for the route
- **Default Socket Path**: Fallback socket for unmatched routes
- **Auth UID**: UID for authentication validation
- **Debug Mode**: Enable verbose logging

## Architecture

- **Epoll-based I/O**: Scalable event-driven architecture supporting up to 64 concurrent clients
- **Ancillary FD Support**: Transparent file descriptor passing through the routing layer
- **Buffer Management**: Per-connection buffers sized dynamically for each message
- **Atomic Operations**: Thread-safe route management

## Limitations

- Maximum 100 routes
- Maximum 64 concurrent clients
- Maximum 16 file descriptors per ancillary data message
- Maximum D-Bus message size of 128MB

## License

This project is licensed under the GNU General Public License v3.0 or later.
See [LICENSE](LICENSE) for the license terms.
