use pop3_server_lib;
use regex::Regex;
use std::io::Read;
use std::io::Write;

// Tests to add
// TODO: Send invalid commands in both modes
// TODO: Send invalid commands after quitting from both modes
// TODO: Read without sending a command first
// TODO: Add incorrect num args tests
// TODO: Add incorrect arg types tests


// Define our dummy server implementation

fn dummy_validate_username_callback(username: &String) -> bool {
    return username == "admin" || username == "user";
}

fn dummy_validate_password_callback(username: &String, password: &String) -> bool {
    return (username == "admin" && password == "password") ||
           (username == "user" && password == "pass");
}

fn dummy_validate_apop_login_callback(
    username: &String,
    digest: &String,
    pid: u32,
    session_start_timestamp: u128,
) -> bool {
    if username != "apop_user" {
        return false;
    }
    let password: &str = "password";
    let login_string: String = format!(
        "<{}.{}@localhost>{}",
        pid,
        session_start_timestamp,
        password,
    );
    println!("{}", login_string);
    let computed_digest = format!("{:x}", md5::compute(login_string.as_bytes()));
    return computed_digest == *digest;
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
                &vec![
                    "test four".to_string(),
                    "...".to_string(),
                    "kind regards, test four".to_string(),
                ],
            ),
            pop3_server_lib::Message::new(
                &vec!["Header5: value5".to_string()],
                &vec!["test five".to_string()],
            ),
        ]
    }
    else if username == "user" || username == "apop_user" {
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
        &"localhost".to_string(),
        |username| dummy_validate_username_callback(username),
        |username, password| dummy_validate_password_callback(username, password),
        Some(|username, digest, pid, session_start_timestamp| dummy_validate_apop_login_callback(username, digest, pid, session_start_timestamp)),
        |username| dummy_retrive_maildrop_callback(username),
        |username, message_number| dummy_delete_message_callback(username, message_number),
    );
}

fn read_greeting(session: &mut pop3_server_lib::POP3ServerSession) -> String {
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response.len(), bytes_read);
    //assert_eq!(response, "+OK POP3 server reporting for duty\r\n");
    let pattern = regex::Regex::new(r"^\+OK POP3 server ready <[0-9]+.[0-9]+@localhost>\r\n$").unwrap();
    if pattern.find(&response).is_none() {
        assert!(false);
    }
    return response;
}

#[test]
fn server_sends_greeting() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();
    read_greeting(&mut session);
}

// USER and PASS Tests

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
    let mut session = server.new_session().unwrap();

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
    let mut session = server.new_session().unwrap();

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
    let mut session = server.new_session().unwrap();

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
fn can_login_after_failed_user_command() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

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

    verify_not_in_transaction_mode(&mut session);

    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
}

#[test]
fn can_login_after_failed_pass_command() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

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

    verify_not_in_transaction_mode(&mut session);

    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
}

#[test]
fn cant_user_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);

    // Send USER command without arguments
    let user_command = "USER admin\r\n";
    session.write(user_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_pass_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);

    // Send PASS command without arguments
    let pass_command = "PASS password\r\n";
    session.write(pass_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_user_after_quitting_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);

    // Send USER command with argument
    let user_command = "USER admin\r\n";
    session.write(user_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_user_after_quitting_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);

    // Send USER command without arguments
    let user_command = "USER admin\r\n";
    session.write(user_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_pass_after_quitting_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);

    // Send PASS command with argument
    let pass_command = "PASS password\r\n";
    session.write(pass_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_pass_after_quitting_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);

    // Send PASS command without arguments
    let pass_command = "PASS password\r\n";
    session.write(pass_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

// APOP Tests

fn generate_apop_digest(
    password: &str,
    greeting: &str,
) -> String {
    let regex = Regex::new(r"(<[^>]*>)").unwrap();
    let caps = regex.captures(greeting).unwrap();
    let login_string: String = format!(
        "{}{}",
        caps.get(1).unwrap().as_str(),
        password,
    );
    println!("{}", login_string);
    let computed_digest = format!("{:x}", md5::compute(login_string.as_bytes()));
    return computed_digest;
}

fn login_with_apop(
    session: &mut pop3_server_lib::POP3ServerSession, 
    username: &str,
    password: &str,
    greeting: &str
) {

    let digest = generate_apop_digest(password, greeting);

    // Send APOP command
    let apop_command = format!("APOP {} {}\r\n", username, digest);
    session.write(apop_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK logged in\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_apop_login_with_valid_credentials() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    let greeting: String = read_greeting(&mut session);
    login_with_apop(
        &mut session, 
        "apop_user",
        "password",
        &greeting,
    );
    verify_transaction_mode(&mut session);
}


#[test]
fn cant_apop_login_with_invalid_username() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    let greeting = read_greeting(&mut session);
    let digest = generate_apop_digest("password", &greeting);

    // Send APOP command
    let apop_command = format!("APOP {} {}\r\n", "admin", digest);
    session.write(apop_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR invalid digest\r\n");
    assert_eq!(response.len(), bytes_read);

    // Check we're not in TRANSACTION mode
    verify_not_in_transaction_mode(&mut session);
}

#[test]
fn cant_apop_login_with_invalid_password() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    let greeting = read_greeting(&mut session);
    let digest = generate_apop_digest("pass", &greeting);

    // Send APOP command
    let apop_command = format!("APOP {} {}\r\n", "apop_user", digest);
    session.write(apop_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR invalid digest\r\n");
    assert_eq!(response.len(), bytes_read);

    // Check we're not in TRANSACTION mode
    verify_not_in_transaction_mode(&mut session);
}

#[test]
fn cant_apop_after_quitting_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    let greeting = read_greeting(&mut session);
    let digest = generate_apop_digest("password", &greeting);
    quit_session(&mut session);


    // Send APOP command
    let apop_command = format!("APOP {} {}\r\n", "apop_user", digest);
    session.write(apop_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);

}

#[test]
fn cant_apop_after_quitting_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    let greeting = read_greeting(&mut session);
    let digest = generate_apop_digest("password", &greeting);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);


    // Send APOP command
    let apop_command = format!("APOP {} {}\r\n", "apop_user", digest);
    session.write(apop_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);

}

// STAT Tests

#[test]
fn can_stat_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send STAT command
    let stat_command = "STAT\r\n";
    session.write(stat_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK 5 199\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_stat_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();
    
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
fn cant_stat_after_quitting_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);

    // Send STAT command with argument
    let stat_command = "STAT\r\n";
    session.write(stat_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_stat_after_quitting_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);

    // Send STAT command without arguments
    let stat_command = "STAT\r\n";
    session.write(stat_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

// LIST Tests

#[test]
fn cant_list_in_authorization_mode_without_arugments() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

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
    let mut session = server.new_session().unwrap();

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
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send LIST command with argument
    let list_command = "LIST\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK scan listing follows\r\n1 29\r\n2 49\r\n3 31\r\n4 60\r\n5 30\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_list_in_transaction_mode_with_argument() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

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
fn cant_list_after_quitting_without_arguments_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);

    // Send LIST command without arguments
    let list_command = "LIST\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_list_after_quitting_with_arguments_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);

    // Send LIST command with argument
    let list_command = "LIST 1\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_list_after_quitting_without_arguments_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);

    // Send LIST command without arguments
    let list_command = "LIST\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_list_after_quitting_with_arguments_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);

    // Send LIST command with argument
    let list_command = "LIST 1\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

// UIDL Tests

#[test]
fn cant_uidl_in_authorization_mode_without_arugments() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);

    // Send UIDL command without argument
    let uidl_command = "UIDL\r\n";
    session.write(uidl_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR not authorized\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_uidl_in_authorization_mode_with_arguments() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);

    // Send UIDL command with argument
    let uidl_command = "UIDL 1\r\n";
    session.write(uidl_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR not authorized\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_uidl_in_transaction_mode_without_argument() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send UIDL command with argument
    let uidl_command = "UIDL\r\n";
    session.write(uidl_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK\r\n1 7c8901ea0f5c27be856b516674b30b4730ecd9864b5e5641064ea276f57e783c\r\n2 f4edc232ed7209f0537222008bbb5b0dfffdb3e212c2085742bb9486f1cb9297\r\n3 636e1c8e29352530ccc5ea0bc1b84c6058f67723dbba94f2c755346e20be90dd\r\n4 cc87b2328631ea44ca6478042bbbe68d1c39c6c9316dfa18ddc882cf6f61d9c2\r\n5 8e44ad6a3dfa06edbbd13aab04068a7d2defa7d5dc28e96c1973d3ee948e83fa\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn can_uidl_in_transaction_mode_with_argument() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send UIDL command with argument
    let uidl_command = "UIDL 1\r\n";
    session.write(uidl_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(
        response, 
        "+OK 1 7c8901ea0f5c27be856b516674b30b4730ecd9864b5e5641064ea276f57e783c\r\n",
    );
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_uidl_after_quitting_without_arguments_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);

    // Send UIDL command without arguments
    let uidl_command = "UIDL\r\n";
    session.write(uidl_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_uidl_after_quitting_with_arguments_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);

    // Send UIDL command with argument
    let uidl_command = "UIDL 1\r\n";
    session.write(uidl_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_uidl_after_quitting_without_arguments_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);

    // Send UIDL command without arguments
    let uidl_command = "UIDL\r\n";
    session.write(uidl_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_uidl_after_quitting_with_arguments_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);

    // Send UIDL command with argument
    let uidl_command = "UIDL 1\r\n";
    session.write(uidl_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

// NOOP Tests

#[test]
fn cant_call_noop_in_authentication_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    verify_not_in_transaction_mode(&mut session);
}

#[test]
fn can_call_noop_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
}

#[test]
fn cant_call_noop_after_quitting_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);

    // Send NOOP command
    let noop_command = "NOOP\r\n";
    session.write(noop_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_call_noop_after_quitting_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);

    // Send NOOP command
    let noop_command = "NOOP\r\n";
    session.write(noop_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

// RETR Tests

#[test]
fn cant_call_retr_in_authentication_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

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
    let mut session = server.new_session().unwrap();

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
fn retr_performs_byte_stuffing() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send RETR command
    let retr_command = "RETR 4\r\n";
    session.write(retr_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK message follows\r\nHeader4: value4\r\n\r\ntest four\r\n....\r\nkind regards, test four\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_retr_after_quitting_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);

    // Send RETR command with argument
    let retr_command = "RETR 2\r\n";
    session.write(retr_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_retr_after_quitting_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);

    // Send RETR command without arguments
    let retr_command = "RETR 2\r\n";
    session.write(retr_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

// TOP Tests

#[test]
fn cant_call_top_in_authentication_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

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
    let mut session = server.new_session().unwrap();

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
    let mut session = server.new_session().unwrap();

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

#[test]
fn top_perform_byte_stuffing() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send TOP command
    let top_command = "TOP 4 2\r\n";
    session.write(top_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK message follows\r\nHeader4: value4\r\n\r\ntest four\r\n....\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);
}


#[test]
fn cant_top_after_quitting_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);

    // Send TOP command with argument
    let top_command = "TOP 2 10\r\n";
    session.write(top_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_top_after_quitting_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);

    // Send TOP command without arguments
    let top_command = "TOP 2 10\r\n";
    session.write(top_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

// DELE Tests

#[test]
fn cant_call_dele_in_authentication_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

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
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    delete_message(&mut session, 1);
}

// Deleting a message changes the output of various other commands
// All of these commands must be tested in concert with DELE

#[test]
fn cant_delete_a_deleted_message() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

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
    let mut session = server.new_session().unwrap();

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
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send STAT command before message is deleted
    let stat_command = "STAT\r\n";
    session.write(stat_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK 5 199\r\n");
    assert_eq!(response.len(), bytes_read);

    delete_message(&mut session, 2);

    // Send STAT command after message is deleted
    let stat_command = "STAT\r\n";
    session.write(stat_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK 4 150\r\n");
    assert_eq!(response.len(), bytes_read);
}


#[test]
fn cant_list_deleted_messages() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

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
fn cant_top_deleted_messages() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send TOP command before message is deleted
    let top_command = "TOP 2 1\r\n";
    session.write(top_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK message follows\r\nHeader2: value2\r\n\r\ntest two\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);

    delete_message(&mut session, 2);

    // Send TOP command after message is deleted
    let top_command = "TOP 2 1\r\n";
    session.write(top_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "-ERR message has been deleted\r\n");
    assert_eq!(response.len(), bytes_read);
}


#[test]
fn deleted_messages_are_no_longer_included_in_list() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);

    // Send LIST command without argument before message is deleted
    let list_command = "LIST\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK scan listing follows\r\n1 29\r\n2 49\r\n3 31\r\n4 60\r\n5 30\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);

    delete_message(&mut session, 2);

    // Send LIST command without argument before message is deleted
    let list_command = "LIST\r\n";
    session.write(list_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "+OK scan listing follows\r\n1 29\r\n3 31\r\n4 60\r\n5 30\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);
}

// TODO: Add test to make sure delted messages aren't show in UIDL listings

#[test]
fn cant_dele_after_quitting_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);

    // Send DELE command with argument
    let dele_command = "DELE 1\r\n";
    session.write(dele_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_dele_after_quitting_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);

    // Send DELE command without arguments
    let dele_command = "DELE 1\r\n";
    session.write(dele_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

// RSET Tests

#[test]
fn cant_rset_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

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
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    call_rset(&mut session);
}

// More RSET tests
#[test]
fn can_read_previously_delted_message_after_rset() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

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


// TODO: add more RSET tests

#[test]
fn cant_rset_after_quitting_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);

    // Send RSET command with argument
    let rset_command = "RSET\r\n";
    session.write(rset_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_rset_after_quitting_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);

    // Send RSET command without arguments
    let rset_command = "RSET\r\n";
    session.write(rset_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

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
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);
}

#[test]
fn can_quit_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    quit_session(&mut session);
}

#[test]
fn cant_quit_after_quitting_in_authorization_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    quit_session(&mut session);

    // Send QUIT command with argument
    let quit_command = "QUIT\r\n";
    session.write(quit_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

#[test]
fn cant_quit_after_quitting_in_transaction_mode() {
    let server = construct_pop3_server();
    let mut session = server.new_session().unwrap();

    read_greeting(&mut session);
    login_with_valid_credentials(&mut session);
    verify_transaction_mode(&mut session);
    quit_session(&mut session);

    // Send QUIT command without arguments
    let quit_command = "QUIT\r\n";
    session.write(quit_command.as_bytes()).unwrap();
    let mut buf: [u8; 512] = [0; 512];
    let bytes_read = session.read(&mut buf).unwrap();
    let response = std::str::from_utf8(&buf).unwrap().trim_matches('\0').to_string();
    assert_eq!(response, "");
    assert_eq!(response.len(), bytes_read);
}

// TODO: Add tests that runs multiple commands in a row after quitting

// Multi session tests

#[test]
fn two_user_can_be_logged_into_two_sessions() {
    let server = construct_pop3_server();
    let mut session1 = server.new_session().unwrap();
    let mut session2 = server.new_session().unwrap();
    
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
    let mut session1 = server.new_session().unwrap();
    let mut session2 = server.new_session().unwrap();
    
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

    let mut session1 = server.new_session().unwrap();
    read_greeting(&mut session1);
    login_with_credentials(
        &mut session1,
        "admin", 
        "password",
    );
    quit_session(&mut session1);

    let mut session2 = server.new_session().unwrap();
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

    let mut session1 = server.new_session().unwrap();
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
    assert_eq!(response, "+OK scan listing follows\r\n1 29\r\n2 49\r\n3 31\r\n4 60\r\n5 30\r\n.\r\n");
    assert_eq!(response.len(), bytes_read);

    let mut session2 = server.new_session().unwrap();
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



