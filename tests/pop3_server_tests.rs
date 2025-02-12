use POP3_server;
use std::io::Read;
use std::io::Write;

// Define out dummy server implementation

fn dummy_validate_username_callback(username: &String) -> bool {
    return username == "admin";
}

fn dummy_validate_password_callback(username: &String, password: &String) -> bool {
    return username == "admin" && password == "password";
}

fn dummy_retrive_maildrop_callback(_username: &String) -> Vec<String> {
    return vec![
        "test one\r\n".to_string(),
        "test two\r\nLets all love lain\r\n".to_string(),
        "test three\r\n".to_string(),
        "test four\r\n".to_string(),
        "test five\r\n".to_string(),
    ]
}

fn dummy_delete_message_callback(_username: &String, _message_number: usize) -> bool {
    return true;
}


fn construct_pop3_server() -> POP3_server::POP3Server {
    return POP3_server::POP3Server{
        locked_users: std::collections::HashSet::new(),
        validate_username_callback: |username| dummy_validate_username_callback(username),
        validate_password_callback: |username, password| dummy_validate_password_callback(username, password),
        retrive_maildrop_callback: |username| dummy_retrive_maildrop_callback(username),
        delete_message_callback: |username, message_number| dummy_delete_message_callback(username, message_number),
    };
}

fn read_greeting(session: &mut POP3_server::POP3ServerSession) {
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(bytes_read, 36);
    assert_eq!(response.len(), 36);
    assert_eq!(response, "+OK POP3 server reporting for duty\r\n");
}

#[test]
fn server_sends_greeting() {
    let mut server = construct_pop3_server();
    let mut session = server.new_session();
    read_greeting(&mut session);
}

fn login_with_valid_credentials(session: &mut POP3_server::POP3ServerSession) {
    // Send USER command
    let user_command = "USER admin\r\n";
    session.write(user_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK user found\r\n");
    assert_eq!(response.len(), bytes_read);

    // Send password
    let pass_command = "PASS password\r\n";
    session.write(pass_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK logged in\r\n");
    assert_eq!(response.len(), bytes_read);
}

fn verify_transaction_mode(session: &mut POP3_server::POP3ServerSession) {
    let noop_command = "NOOP\r\n";
    session.write(noop_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_login_with_valid_credentials() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
}


fn verify_not_in_transaction_mode(session: &mut POP3_server::POP3ServerSession) {
    let noop_command = "NOOP\r\n";
    session.write(noop_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR not authorized\r\n");
    assert_eq!(response.len(), bytes_read);
}


#[test]
fn cant_login_with_invalid_username() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    // Read greeting
    read_greeting(&mut session);

    // Send USER command with invalid username
    let user_command = "USER lain\r\n";
    session.write(user_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR no mailbox exists for specified user\r\n");
    assert_eq!(response.len(), bytes_read);

    // Check we're not in TRANSACTION mode
    verify_not_in_transaction_mode(&mut session);
}

#[test]
fn cant_login_with_invalid_password() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    // Read greeting
    read_greeting(&mut session);

    // Send USER command with valid username
    let user_command = "USER admin\r\n";
    session.write(user_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK user found\r\n");
    assert_eq!(response.len(), bytes_read);

    // Send PASS command with incorrect password
    let pass_command = "PASS lain\r\n";
    session.write(pass_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR invalid password\r\n");
    assert_eq!(response.len(), bytes_read);

    // Check we're not in TRANSACTION mode
    verify_not_in_transaction_mode(&mut session);
}

#[test]
fn can_stat_in_transaction_mode() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send STAT command
    let stat_command = "STAT\r\n";
    session.write(stat_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK 5 74\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_stat_in_authorization_mode() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();
    
    read_greeting(&mut session);

    // Send STAT command
    let stat_command = "STAT\r\n";
    session.write(stat_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR not authorized\r\n");
    assert_eq!(response.len(), bytes_read);
}


#[test]
fn cant_list_in_authorization_mode_without_arugments() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);

    // Send LIST command without argument
    let list_command = "LIST\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR not authorized\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_list_in_authorization_mode_with_arguments() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);

    // Send LIST command with argument
    let list_command = "LIST 1\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR not authorized\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_list_in_transaction_mode_without_argument() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send LIST command with argument
    let list_command = "LIST\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK scan listing follows\r\n0 10\r\n1 30\r\n2 12\r\n3 11\r\n4 11\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_list_in_transaction_mode_with_argument() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send LIST command with argument
    let list_command = "LIST 2\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK 2 12\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_call_noop_in_authentication_mode() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    verify_not_in_transaction_mode(&mut session);
}

#[test]
fn can_call_noop_in_transaction_mode() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
}


#[test]
fn cant_call_retr_in_authentication_mode() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    // Send RETR command
    let retr_command = "RETR 1\r\n";
    session.write(retr_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR not authorized\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_call_retr_in_transaction_mode() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send RETR command
    let retr_command = "RETR 1\r\n";
    session.write(retr_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK message follows\r\ntest two\r\nLets all love lain\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_call_dele_in_authentication_mode() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    // Send DELE command
    let dele_command = "DELE 1\r\n";
    session.write(dele_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR not authorized\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_call_dele_in_transaction_mode() {
    // Create session
    let mut server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send DELE command
    let dele_command = "DELE 1\r\n";
    session.write(dele_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK message deleted\r\n");
    assert_eq!(response.len(), bytes_read);
}

// Deleting a message changes the output of various other commands
// All of these commands must be tested in concert with DELE
