# POP3 Server Library

This repo contains a full implementation of the POP3 server interface, as specified in RFC-1939, in the rust programming language. 
In order to make the library as widely applicable and useful as possible no client facing network, or backend email storage and retrieval implementation is included as part of it.
The specifics of these design choices are left up to the consumer of the library although we give an example implementation [Add link to sister repo with implementation]().

## Testing

This project contains a comprehensive tests suite designed to full test each of the POP3 commands included in RFC-1939.
These tests can be found in `tests/pop3_server_lib_tests.rs` and can trivially using `cargo` as follows:
```bash
cargo test
```


