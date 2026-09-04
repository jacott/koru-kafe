# Kafe (Koru Accelerated Front End)

Kafe is a front end server written in Rust, designed specifically to work with the **Koru** Node.js
framework. It is intended to replace Nginx in the Koru stack, providing a high-performance entry
point for application traffic.

## Project Goal
While Kafe currently functions as a specialized replacement for Nginx, the long-term goal of the
project is to accelerate Koru applications by moving and duplicating performance-critical
functionality from the Node.js layer into the Rust environment.


## Testing
Requires local postgresql with the following setup:

```sh
sudo -u postgres createuser -drs $USER

createdb $USER
createdb koru-kafe-test
```

## License

MIT license ([LICENSE-MIT][6] or <http://opensource.org/licenses/MIT>)
