use pop3_server_lib;
use std::io::Read;
use std::io::Write;

// Define out dummy server implementation

fn dummy_validate_username_callback(username: &String) -> bool {
    return username == "admin" || username == "user";
}

fn dummy_validate_password_callback(username: &String, password: &String) -> bool {
    return (username == "admin" && password == "password") ||
           (username == "user" && password == "pass");
}

fn dummy_retrive_maildrop_callback(username: &String) -> Vec<pop3_server_lib::Message> {
    if username == "admin" {
        return vec![
            pop3_server_lib::Message::new(
                &vec!["Header1: value1".to_string()],
                &vec!["test one".to_string()],
            ),
            pop3_server_lib::Message::new(
                &vec!["Header2: value2".to_string()],
                &vec![
                    "test two".to_string(),
                    "Lets all love lain".to_string(),
                ],
            ),
            pop3_server_lib::Message::new(
                &vec!["Header3: value3".to_string()],
                &vec!["test three".to_string()],
            ),
            pop3_server_lib::Message::new(
                &vec!["Header4: value4".to_string()],
                &vec!["test four".to_string()],
            ),
            pop3_server_lib::Message::new(
                &vec!["Header5: value5".to_string()],
                &vec!["test five".to_string()],
            ),
        ]
    }
    else if username == "user" {
        return vec![
            pop3_server_lib::Message::new(
                &vec!["TestHeader: test_value".to_string()],
                &vec!["this is a test".to_string()],
            ),
            pop3_server_lib::Message::new(
                &vec!["LainHeader: 141N".to_string()],
                &vec![
                    "test this!".to_string(),
                    "Lets all love lain".to_string(),
                ],
            ),
        ]
    }
    else {
        assert!(false);
        return vec![];
    }
}

fn dummy_delete_message_callback(_username: &String, _message_number: usize) -> bool {
    return true;
}


fn construct_pop3_server() -> pop3_server_lib::POP3Server {
    return pop3_server_lib::POP3Server::new(
         |username| dummy_validate_username_callback(username),
         |username, password| dummy_validate_password_callback(username, password),
        |username| dummy_retrive_maildrop_callback(username),
        |username, message_number| dummy_delete_message_callback(username, message_number),
    );
}

fn read_greeting(session: &mut pop3_server_lib::POP3ServerSession) {
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(bytes_read, 36);
    assert_eq!(response.len(), 36);
    assert_eq!(response, "+OK POP3 server reporting for duty\r\n");
}

#[test]
fn server_sends_greeting() {
    let server = construct_pop3_server();
    let mut session = server.new_session();
    read_greeting(&mut session);
}

fn login_with_valid_credentials(session: &mut pop3_server_lib::POP3ServerSession) {
    login_with_credentials(session, "admin", "password");
}

fn login_with_credentials(
    session: &mut pop3_server_lib::POP3ServerSession, 
    username: &str,
    password: &str,
) {
    // Send USER command
    let user_command = format!("USER {}\r\n", username);
    session.write(user_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK user found\r\n");
    assert_eq!(response.len(), bytes_read);

    // Send password
    let pass_command = format!("PASS {}\r\n", password);
    session.write(pass_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK logged in\r\n");
    assert_eq!(response.len(), bytes_read);
}

fn verify_transaction_mode(session: &mut pop3_server_lib::POP3ServerSession) {
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
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
}


fn verify_not_in_transaction_mode(session: &mut pop3_server_lib::POP3ServerSession) {
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
    let server = construct_pop3_server();
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
    let server = construct_pop3_server();
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
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send STAT command
    let stat_command = "STAT\r\n";
    session.write(stat_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK 5 169\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_stat_in_authorization_mode() {
    let server = construct_pop3_server();
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
    let server = construct_pop3_server();
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
    let server = construct_pop3_server();
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
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send LIST command with argument
    let list_command = "LIST\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK scan listing follows\r\n1 29\r\n2 49\r\n3 31\r\n4 30\r\n5 30\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_list_in_transaction_mode_with_argument() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send LIST command with argument
    let list_command = "LIST 3\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK 3 31\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_call_noop_in_authentication_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    verify_not_in_transaction_mode(&mut session);
}

#[test]
fn can_call_noop_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
}


#[test]
fn cant_call_retr_in_authentication_mode() {
    let server = construct_pop3_server();
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
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send RETR command
    let retr_command = "RETR 2\r\n";
    session.write(retr_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK message follows\r\nHeader2: value2\r\n\r\ntest two\r\nLets all love lain\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_call_top_in_authentication_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    // Send TOP command
    let top_command = "TOP 2 1\r\n";
    session.write(top_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR not authorized\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_call_top_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send TOP command
    let top_command = "TOP 2 1\r\n";
    session.write(top_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK message follows\r\nHeader2: value2\r\n\r\ntest two\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn calling_top_with_too_large_num_lines_gives_whole_message() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send RETR command
    let top_command = "TOP 2 10\r\n";
    session.write(top_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK message follows\r\nHeader2: value2\r\n\r\ntest two\r\nLets all love lain\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);
}
// DELE Tests

#[test]
fn cant_call_dele_in_authentication_mode() {
    let server = construct_pop3_server();
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

fn delete_message(
    session: &mut pop3_server_lib::POP3ServerSession,
    message_number: usize,
) {
    // Send DELE command
    let dele_command = format!("DELE {}\r\n", message_number);
    session.write(dele_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK message deleted\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_call_dele_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    delete_message(&mut session, 1);
}

// Deleting a message changes the output of various other commands
// All of these commands must be tested in concert with DELE

#[test]
fn cant_delete_a_deleted_message() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    delete_message(&mut session, 1);

    // Send DELE command
    let dele_command = "DELE 1\r\n";
    session.write(dele_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR message already deleted\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_read_a_deleted_message() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    delete_message(&mut session, 1);

    // Send RETR command
    let retr_command = "RETR 1\r\n";
    session.write(retr_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR message has been deleted\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn deleted_messages_are_no_longer_included_in_stat_total() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send STAT command before message is deleted
    let stat_command = "STAT\r\n";
    session.write(stat_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK 5 169\r\n");
    assert_eq!(response.len(), bytes_read);

    delete_message(&mut session, 2);

    // Send STAT command after message is deleted
    let stat_command = "STAT\r\n";
    session.write(stat_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK 4 120\r\n");
    assert_eq!(response.len(), bytes_read);
}


#[test]
fn cant_list_deleted_messages() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send LIST command with argument before message is deleted
    let list_command = "LIST 3\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK 3 31\r\n");
    assert_eq!(response.len(), bytes_read);

    delete_message(&mut session, 3);

    // Send LIST command with argument after message is deleted
    let list_command = "LIST 3\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR message has been deleted\r\n");
    assert_eq!(response.len(), bytes_read);
}


#[test]
fn deleted_messages_are_no_longer_included_in_list() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send LIST command without argument before message is deleted
    let list_command = "LIST\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK scan listing follows\r\n1 29\r\n2 49\r\n3 31\r\n4 30\r\n5 30\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);

    delete_message(&mut session, 2);

    // Send LIST command without argument before message is deleted
    let list_command = "LIST\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK scan listing follows\r\n1 29\r\n3 31\r\n4 30\r\n5 30\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_rset_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);

    // Send RSET command
    let rset_command = "RSET\r\n";
    session.write(rset_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR not authorized\r\n");
    assert_eq!(response.len(), bytes_read);
}

fn call_rset(session: &mut pop3_server_lib::POP3ServerSession) {
    // Send RSET command
    let rset_command = "RSET\r\n";
    session.write(rset_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_rset_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    call_rset(&mut session);
}

// More RSET tests
#[test]
fn can_read_previously_delted_message_after_rset() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send LIST command with argument before message is deleted
    let list_command = "LIST 3\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK 3 31\r\n");
    assert_eq!(response.len(), bytes_read);

    delete_message(&mut session, 3);

    // Send LIST command with argument after message is deleted
    let list_command = "LIST 3\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR message has been deleted\r\n");
    assert_eq!(response.len(), bytes_read);

    call_rset(&mut session);

    // Send LIST command with argument after message is deleted and RSET called
    let list_command = "LIST 3\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK 3 31\r\n");
    assert_eq!(response.len(), bytes_read);
}

// Could add more RSET tests

// QUIT tests

fn quit_session(session: &mut pop3_server_lib::POP3ServerSession) {
    // Send USER command
    let user_command = "QUIT\r\n";
    session.write(user_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK POP3 server signing off\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_quit_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    quit_session(&mut session);
}

#[test]
fn can_quit_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    quit_session(&mut session);
}

#[test]
fn all_commands_are_ignored_after_quit() {
    // I just want to test that after calling quit every command results
    // in no data being buffered for reading
}


// Multi session tests

#[test]
fn two_user_can_be_logged_into_two_sessions() {
    let server = construct_pop3_server();
    let mut session1 = server.new_session();
    let mut session2 = server.new_session();
    
    read_greeting(&mut session1);
    login_with_credentials(
        &mut session1,
        "admin", 
        "password",
    );

    read_greeting(&mut session2);
    login_with_credentials(
        &mut session2,
        "user", 
        "pass",
    );
}

#[test]
fn user_cant_log_into_two_sessions() {
    let server = construct_pop3_server();
    let mut session1 = server.new_session();
    let mut session2 = server.new_session();
    
    read_greeting(&mut session1);
    login_with_credentials(
        &mut session1,
        "admin", 
        "password",
    );

    read_greeting(&mut session2);
    // Send USER command
    let user_command = "USER admin\r\n";
    session2.write(user_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session2.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK user found\r\n");
    assert_eq!(response.len(), bytes_read);

    // Send password
    let pass_command = "PASS password\r\n";
    session2.write(pass_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session2.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR maildrop already locked\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn user_can_login_quit_and_login_to_a_new_session() {
    let server = construct_pop3_server();

    let mut session1 = server.new_session();
    read_greeting(&mut session1);
    login_with_credentials(
        &mut session1,
        "admin", 
        "password",
    );
    quit_session(&mut session1);

    let mut session2 = server.new_session();
    read_greeting(&mut session2);
    login_with_credentials(
        &mut session2,
        "admin", 
        "password",
    );
}

#[test]
fn different_users_have_different_maildrops_with_simulatenous_sessions() {
    let server = construct_pop3_server();

    let mut session1 = server.new_session();
    read_greeting(&mut session1);
    login_with_credentials(
        &mut session1,
        "admin", 
        "password",
    );
    let list_command = "LIST\r\n";
    session1.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session1.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK scan listing follows\r\n1 29\r\n2 49\r\n3 31\r\n4 30\r\n5 30\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);

    let mut session2 = server.new_session();
    read_greeting(&mut session2);
    login_with_credentials(
        &mut session2,
        "user", 
        "pass",
    );
    let list_command = "LIST\r\n";
    session2.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session2.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK scan listing follows\r\n1 42\r\n2 52\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);
}



