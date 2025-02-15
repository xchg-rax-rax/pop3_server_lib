//TODO: Implement APOP command
//TODO: byte stuffing
//TODO: Make sure byte totals are correct 
//TODO: General Tidying
//TODO: General Tidying
//TODO: Do tagged releases
//TODO: Add docs
use sha2::{Sha256, Digest};

#[derive(PartialEq)]
enum POP3ServerSessionStates {
    AuthorizationUser,
    AuthorizationPass,
    Transaction,
    Update,
    Done,
}

pub struct POP3Server {
    locked_users: std::sync::RwLock<std::collections::HashSet<String>>,
    validate_username_callback: fn(&String) -> bool,
    validate_password_callback: fn(&String, &String) -> bool,
    retrive_maildrop_callback: fn(&String) -> Vec<Message>,
    delete_message_callback: fn(&String, usize) -> bool,
}

impl POP3Server {
    pub fn new(
        validate_username_callback: fn(&String) -> bool,
        validate_password_callback: fn(&String, &String) -> bool,
        retrive_maildrop_callback: fn(&String) -> Vec<Message>,
        delete_message_callback: fn(&String, usize) -> bool,
    ) -> Self {
        let pop3_server: POP3Server = POP3Server{
            locked_users: std::sync::RwLock::new(std::collections::HashSet::new()),
            validate_username_callback,
            validate_password_callback,
            retrive_maildrop_callback,
            delete_message_callback,
        };
        return pop3_server
    }

    pub fn new_session (&self) -> POP3ServerSession {
        return POP3ServerSession::new(self)
    }

    pub fn lock_user(&self, username: &String) {
        let mut locked_users = self.locked_users.write().unwrap();
        locked_users.insert(username.clone());
    }

    pub fn unlock_user(&self, username: &String) {
        let mut locked_users = self.locked_users.write().unwrap();
        locked_users.remove(username);
    }

    pub fn check_user_lock(&self, username: &String) -> bool {
        let locked_users = self.locked_users.read().unwrap();
        return locked_users.contains(username);
    }

    fn retrive_maildrop(&self, username: &String) -> Vec<Message> {
        return (self.retrive_maildrop_callback)(username);
    }

    fn validate_username(&self, username: &String) -> bool {
        return (self.validate_username_callback)(username)
    }

    fn validate_password(&self, username: &String, password: &String) -> bool {
        return (self.validate_password_callback)(username, password)
    }

    fn delete_message(&self, username: &String, message_number: usize) -> bool {
        return (self.delete_message_callback)(username, message_number)
    }
}

pub struct Message {
    headers: Vec<String>,
    body: Vec<String>,
    size: usize,
    deleted: bool,
}

impl Message {
    pub fn new(
        headers: &Vec<String>,
        body: &Vec<String>,
    ) -> Self {
        // TODO: Account for byte stuffing
        // TODO: Verify this calculation is correct see section 11 of RFC-1939
        let mut total_size = 0;
        for header in headers {
            total_size += header.len() + 2;
        }
        // Add two bytes for blank line between header and body
        total_size += 2;
        for line in body {
            total_size += line.len() + 2;
        }
        return Message {
            headers: headers.clone(),
            body: body.clone(),
            size: total_size,
            deleted: false,
        }
    }

    pub fn get_message_bytes(&self) -> Vec<u8> {
        let mut output = String::new();
        for header in &self.headers {
            output += header;
            output += "\r\n";
        }
        output += "\r\n";
        for line in &self.body {
            output += line ;
            output += "\r\n";
        }
        return output.into_bytes();
    }

    pub fn get_message_top_bytes(&self, number_of_lines: usize) -> Vec<u8> {
        let acutal_number_of_lines: usize = std::cmp::min(
            number_of_lines,
            self.body.len(),
        );

        let mut output = String::new();
        for header in &self.headers {
            output += header;
            output += "\r\n";
        }
        output += "\r\n";
        for i in 0..acutal_number_of_lines {
            output += self.body.get(i).unwrap(); // TODO: sus
            output += "\r\n";
        }
        return output.into_bytes();
    }

    pub fn compute_message_hash(&self) -> String {
        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(self.get_message_bytes());
        let result = sha256_hasher.finalize();
        let hex_hash = format!("{:x}", result);
        return hex_hash
    }
}

struct Command {
    keyword: String,
    arguments: Vec<String> }


pub struct POP3ServerSession<'a> {
    server: &'a POP3Server, // Sever that created the session
    state: POP3ServerSessionStates,
    username: String,
    input_buffer: Vec<u8>,
    output_buffer: Vec<u8>,
    maildrop: Vec<Message>,
}

impl<'a> POP3ServerSession<'a> {
    fn new(server: &'a POP3Server) -> Self {
        let mut instance: Self = POP3ServerSession{
            server: server,
            state: POP3ServerSessionStates::AuthorizationUser,
            username: String::from(""),
            input_buffer: Vec::new(),
            output_buffer: Vec::new(),
            maildrop: Vec::new(),
        };
        instance.send_greeting(); return instance;
    }

    // Send greeting to client after connection completed
    fn send_greeting(&mut self) {
        self.output_buffer.extend(b"+OK POP3 server reporting for duty\r\n");
    }
   

    // ---------------------------- //
    // AUTHORIZATION State Commands //
    // ---------------------------- //
   
    // USER
    fn user(&mut self, username: &String) {
        if self.state != POP3ServerSessionStates::AuthorizationUser {
            self.output_buffer.extend(b"-ERR\r\n"); // Think of better error
            return;
        }
        let is_username_valid = self.server.validate_username(username);
        if !is_username_valid {
            self.output_buffer.extend(b"-ERR no mailbox exists for specified user\r\n");
            return;
        }
        self.username = username.clone();
        self.state = POP3ServerSessionStates::AuthorizationPass;
        self.output_buffer.extend(b"+OK user found\r\n");
    }

    fn pass(&mut self, password: &String) {
        if self.state != POP3ServerSessionStates::AuthorizationPass {
            self.output_buffer.extend(b"-ERR\r\n"); // TODO:  Think of better error
            return;
        }
        if self.server.check_user_lock(&self.username) {
            self.output_buffer.extend(b"-ERR maildrop already locked\r\n");
            return;
        }
        let is_password_valid = self.server.validate_password(
            &self.username,
            password,
        );
        if !is_password_valid {
            self.state = POP3ServerSessionStates::AuthorizationUser;
            self.output_buffer.extend(b"-ERR invalid password\r\n");
            return;
        }

        // Obtain lock for user
        self.server.lock_user(&self.username);

        self.maildrop = self.server.retrive_maildrop(&self.username);
        
        self.state = POP3ServerSessionStates::Transaction;
        self.output_buffer.extend(b"+OK logged in\r\n");
    }

    // Will need this if we ever add raw Message parsing
    /*
    fn format_maildrop(raw_maildrop: &Vec<String>) -> Vec<Message> {
        let mut formatted_maildrop: Vec<Message> = Vec::new();
        for raw_message in raw_maildrop {
            formatted_maildrop.push(
                Message{
                    body: raw_message.clone(), // Add byte packing logic
                    deleted: false,
                },
            );
        }
        return formatted_maildrop;
    }
    */

    // -------------------------- //
    // Transaction State Commands //
    // -------------------------- //

    // STAT command
    fn stat(&mut self) {
        if self.state != POP3ServerSessionStates::Transaction {
            self.output_buffer.extend(b"-ERR not authorized\r\n");
            return;
        }
        let number_of_messages: usize = POP3ServerSession::compute_number_of_messages(
            &self.maildrop,
        );
        let maildrop_size_in_bytes: usize = POP3ServerSession::compute_maildrop_size(
            &self.maildrop,
        );
        self.output_buffer.extend(
            format!(
                "+OK {} {}\r\n",
                number_of_messages,
                maildrop_size_in_bytes,
            ).as_bytes(),
        );
    }

    fn compute_number_of_messages(maildrop: &Vec<Message>) -> usize {
        let mut number_of_messages: usize = 0;
        for message in maildrop {
            if message.deleted {
                continue;
            }
            number_of_messages += 1;
        }
        return number_of_messages;
    }

    // TODO: This may be incorrect
    fn compute_maildrop_size(maildrop: &Vec<Message>) -> usize {
        let mut total_size: usize = 0;
        for message in maildrop {
            if message.deleted {
                continue;
            }
            total_size += message.size;
        }
        return total_size;
    }

    // LIST command
    fn list(&mut self, message_number: Option<usize>) {
        if self.state != POP3ServerSessionStates::Transaction {
            self.output_buffer.extend(b"-ERR not authorized\r\n");
            return;
        }
        match message_number {
            Some(message_number ) => {
                self.list_single_message(message_number);
            }
            None => {
                self.list_all_messages();
            }
        }
    }

    fn list_single_message(&mut self, message_number: usize) {
        let message: Option<&Message> = self.maildrop.get(message_number - 1);
        match message {
            Some(message) => {
                if message.deleted {
                    self.output_buffer.extend(b"-ERR message has been deleted\r\n");
                    return
                }
                self.output_buffer.extend(
                    format!(
                        "+OK {} {}\r\n",
                        message_number,
                        message.size,
                    ).as_bytes(),
                );
            }
            None => {
                self.output_buffer.extend(
                    format!(
                        "-ERR no such message, only {}\r\n",
                        self.maildrop.len(),
                    ).as_bytes(),
                );
            }
        }
    }

    fn list_all_messages(&mut self) {
        self.output_buffer.extend(b"+OK scan listing follows\r\n");
        for (message_number, message) in self.maildrop.iter().enumerate() {
            if message.deleted {
                continue;
            }
            self.output_buffer.extend(
                format!(
                    "{} {}\r\n",
                    message_number + 1,
                    message.size,
                ).as_bytes(),
            );
        }
        self.output_buffer.extend(b".\r\n");
    }

    // UIDL command
    fn uidl(&mut self, message_number: Option<usize>) {
        if self.state != POP3ServerSessionStates::Transaction {
            self.output_buffer.extend(b"-ERR not authorized\r\n");
            return;
        }
        match message_number {
            Some(message_number ) => {
                self.uidl_single_message(message_number);
            }
            None => {
                self.uidl_all_messages();
            }
        }
    }

    fn uidl_single_message(&mut self, message_number: usize) {
        let message: Option<&Message> = self.maildrop.get(message_number - 1);
        match message {
            Some(message) => {
                if message.deleted {
                    self.output_buffer.extend(b"-ERR message has been deleted\r\n");
                    return
                }
                self.output_buffer.extend(
                    format!(
                        "+OK {} {}\r\n",
                        message_number,
                        message.compute_message_hash(), 
                    ).as_bytes(),
                );
            }
            None => {
                self.output_buffer.extend(
                    format!(
                        "-ERR no such message, only {}\r\n",
                        self.maildrop.len(),
                    ).as_bytes(),
                );
            }
        }
    }

    fn uidl_all_messages(&mut self) {
        self.output_buffer.extend(b"+OK\r\n");
        for (message_number, message) in self.maildrop.iter().enumerate() {
            if message.deleted {
                continue;
            }
            self.output_buffer.extend(
                format!(
                    "{} {}\r\n",
                    message_number + 1,
                    message.compute_message_hash(),
                ).as_bytes(),
            );
        }
        self.output_buffer.extend(b".\r\n");
    }


    // RETR
    fn retr(&mut self, message_number: usize) {
        if self.state != POP3ServerSessionStates::Transaction {
            self.output_buffer.extend(b"-ERR not authorized\r\n");
            return;
        }
        let message: Option<&Message> = self.maildrop.get(message_number - 1);
        match message {
            Some(message) => {
                if message.deleted {
                    self.output_buffer.extend(b"-ERR message has been deleted\r\n");
                    return
                }
                self.output_buffer.extend(b"+OK message follows\r\n");
                // Send message (should already be formatted and byte stuffed)
                self.output_buffer.extend(message.get_message_bytes());
                // Send termination character
                self.output_buffer.extend(b".\r\n");
            }
            None => {
                self.output_buffer.extend(b"-ERR no such message\r\n");
            }
        }
    }

    // DELE
    fn dele(&mut self, message_number: usize) {
        if self.state != POP3ServerSessionStates::Transaction {
            self.output_buffer.extend(b"-ERR not authorized\r\n");
            return;
        }
        let message: Option<&mut Message> = self.maildrop.get_mut(message_number - 1);
        match message {
            Some(message) => {
                if message.deleted {
                    self.output_buffer.extend(b"-ERR message already deleted\r\n");
                    return
                }
                message.deleted = true;
                self.output_buffer.extend(b"+OK message deleted\r\n");
            }
            None => {
                self.output_buffer.extend(b"-ERR no such message\r\n");
            }
        }
    }

    // NOOP
    fn noop(&mut self) {
        if self.state != POP3ServerSessionStates::Transaction {
            self.output_buffer.extend(b"-ERR not authorized\r\n");
            return;
        }
        self.output_buffer.extend(b"+OK\r\n");
    }

    // RSET
    fn rset(&mut self) {
        if self.state != POP3ServerSessionStates::Transaction {
            self.output_buffer.extend(b"-ERR not authorized\r\n");
            return;
        }
        for message in self.maildrop.iter_mut() {
            message.deleted = false;
        }
        self.output_buffer.extend(b"+OK\r\n");
    }

    // TOP
    fn top(
        &mut self,
        message_number: usize,
        number_of_lines: usize,
    ) {
        if self.state != POP3ServerSessionStates::Transaction {
            self.output_buffer.extend(b"-ERR not authorized\r\n");
            return;
        }
        let message: Option<&mut Message> = self.maildrop.get_mut(message_number - 1);
        match message {
            Some(message) => {
                if message.deleted {
                    self.output_buffer.extend(b"-ERR message has been deleted\r\n");
                    return
                }
                self.output_buffer.extend(b"+OK message follows\r\n");
                // Send message (should already be formatted and byte stuffed)
                self.output_buffer.extend(
                    message.get_message_top_bytes(
                        number_of_lines,
                    ),
                );
                // Send termination character
                self.output_buffer.extend(b".\r\n");
            }
            None => {
                self.output_buffer.extend(b"-ERR no such message\r\n");
            }
        }
    }

    // --------------------- //
    // Update State Commands //
    // --------------------- //
    

    // QUIT command
    fn quit(&mut self) {
        let mut update_succesful: bool = true;
        if self.state == POP3ServerSessionStates::Transaction {
            self.state = POP3ServerSessionStates::Update;
            // Delete any messages marked for deletion
            for (message_number, message) in self.maildrop.iter().enumerate() {
                if message.deleted {
                    let was_message_deleted = self.server.delete_message(
                        &self.username,
                        message_number,
                    );
                    if !was_message_deleted {
                        update_succesful = false;
                    }
                }
            }
            // Release lock for user
            self.server.unlock_user(&self.username);
        }

        if update_succesful {
            self.output_buffer.extend(b"+OK POP3 server signing off\r\n");
            self.state = POP3ServerSessionStates::Done;
        } else {
            self.output_buffer.extend(b"-ERR some deleted messages not removed\r\n");
            self.state = POP3ServerSessionStates::Done;
        }
    }


    // --------------------- //
    // Command Parsing Logic //
    // --------------------- //


    // This argument parsing logic could do with refactoring

    fn process_command(&mut self) {
        let command: Command = match self.read_command_from_buffer() {
            Some(command) => command,
            None => {
                // No command pending so do nothing
                return;
            }
        };
        
        let mut command_parsed_successfully: bool = false;
        match command.keyword.as_str() {
            "USER" => {
                command_parsed_successfully = self.parse_user_command(&command.arguments);
            },
            "PASS" => {
                command_parsed_successfully = self.parse_pass_command(&command.arguments);
            },
            "STAT" => {
                command_parsed_successfully = self.parse_stat_command(&command.arguments);
            },
            "LIST" => {
                command_parsed_successfully = self.parse_list_command(&command.arguments);
            },
            "UIDL" => {
                command_parsed_successfully = self.parse_uidl_command(&command.arguments);
            },
            "RETR" => {
                command_parsed_successfully = self.parse_retr_command(&command.arguments);
            },
            "TOP" => {
                command_parsed_successfully = self.parse_top_command(&command.arguments);
            },
            "DELE" => {
                command_parsed_successfully = self.parse_dele_command(&command.arguments);
            },
            "NOOP" => {
                command_parsed_successfully = self.parse_noop_command(&command.arguments);
            },
            "RSET" => {
                command_parsed_successfully = self.parse_rset_command(&command.arguments);
            },
            "QUIT" => {
                command_parsed_successfully = self.parse_quit_command(&command.arguments);
            },
            _ => {
                // Do nothing
            }
        }
        if !command_parsed_successfully {
            self.output_buffer.extend(b"-ERR Invalid command\r\n");
        }
    }

    fn parse_user_command(&mut self, arguments: &Vec<String>) -> bool {
        if arguments.len() != 1 {
            return false;
        }
        let username: &String = match arguments.get(0) {
            Some(username) => username,
            None => {
                return false;
            }
        };
        self.user(username);
        return true;
    }

    fn parse_pass_command(&mut self, arguments: &Vec<String>) -> bool {
        if arguments.len() != 1 {
            return false;
        }
        let password: &String = match arguments.get(0) {
            Some(password) => password,
            None => {
                return false;
            }
        };
        self.pass(password);
        return true;
    }

    fn parse_stat_command(&mut self, arguments: &Vec<String>) -> bool {
        if arguments.len() != 0 {
            return false;
        }
        self.stat();
        return true;
    }

    fn parse_list_command(&mut self, arguments: &Vec<String>) -> bool {
        if arguments.len() == 0 {
            self.list(None);
            return true;
        } else if arguments.len() == 1 {
            let raw_message_number: &String = match arguments.get(0) {
                Some(raw_message_number) => raw_message_number,
                None => {
                    return false;
                }
            };
            let message_number = match raw_message_number.parse::<usize>() {
                Ok(message_number) => message_number,
                Err(_) => {
                    return false;
                }
            };
            self.list(Some(message_number));
            return true;
        } else {
            return false;
        }
    }

    fn parse_uidl_command(&mut self, arguments: &Vec<String>) -> bool {
        if arguments.len() == 0 {
            self.uidl(None);
            return true;
        } else if arguments.len() == 1 {
            let raw_message_number: &String = match arguments.get(0) {
                Some(raw_message_number) => raw_message_number,
                None => {
                    return false;
                }
            };
            let message_number = match raw_message_number.parse::<usize>() {
                Ok(message_number) => message_number,
                Err(_) => {
                    return false;
                }
            };
            self.uidl(Some(message_number));
            return true;
        } else {
            return false;
        }
    }
    
    fn parse_retr_command(&mut self, arguments: &Vec<String>) -> bool {
        if arguments.len() != 1 {
            return false;
        }
        let raw_message_number: &String = match arguments.get(0) {
            Some(raw_message_number) => raw_message_number,
            None => {
                return false;
            }
        };
        let message_number = match raw_message_number.parse::<usize>() {
            Ok(message_number) => message_number,
            Err(_) => {
                return false;
            }
        };
        self.retr(message_number);
        return true;
    }

    fn parse_top_command(&mut self, arguments: &Vec<String>) -> bool {
        if arguments.len() != 2 {
            return false;
        }
        let raw_message_number: &String = match arguments.get(0) {
            Some(raw_message_number) => raw_message_number,
            None => {
                return false;
            }
        };
        let message_number: usize = match raw_message_number.parse::<usize>() {
            Ok(message_number) => message_number,
            Err(_) => {
                return false;
            }
        };
        let raw_number_of_lines: &String = match arguments.get(1) {
            Some(raw_number_of_lines) => raw_number_of_lines,
            None => {
                return false;
            }
        };
        let number_of_lines: usize = match raw_number_of_lines.parse::<usize>() {
            Ok(number_of_lines) => number_of_lines,
            Err(_) => {
                return false;
            }
        };
        self.top(message_number, number_of_lines);
        return true;
    }

    fn parse_dele_command(&mut self, arguments: &Vec<String>) -> bool {
        if arguments.len() != 1 {
            return false;
        }
        let raw_message_number: &String = match arguments.get(0) {
            Some(raw_message_number) => raw_message_number,
            None => {
                return false;
            }
        };
        let message_number = match raw_message_number.parse::<usize>() {
            Ok(message_number) => message_number,
            Err(_) => {
                return false;
            }
        };
        self.dele(message_number);
        return true;
    }

    fn parse_noop_command(&mut self, arguments: &Vec<String>) -> bool {
        if arguments.len() != 0 {
            return false;
        }
        self.noop();
        return true;
    }

    fn parse_rset_command(&mut self, arguments: &Vec<String>) -> bool {
        if arguments.len() != 0 {
            return false;
        }
        self.rset();
        return true;
    }

    fn parse_quit_command(&mut self, arguments: &Vec<String>) -> bool {
        if arguments.len() != 0 {
            return false;
        }
        self.quit();
        return true;
    }


    fn read_command_from_buffer(&mut self) -> Option<Command>  {
        let input_buffer_str = String::from_utf8_lossy(&self.input_buffer);
        let lines: Vec<&str> = input_buffer_str
            .split("\r\n")
            .collect();

        let raw_command: &str = match lines.get(0) {
            Some(raw_command) => *raw_command,
            None => {
                return None;
            }
        };
        if raw_command == "" {
            return None;
        }

        let command: Command = POP3ServerSession::parse_command(raw_command);
        // Remove command from input buffer
        self.input_buffer.drain(0..raw_command.len()+2); // TODO: fix this
        return Some(command);
    }

    fn parse_command(raw_command: &str) -> Command {
        let command_parts: Vec<&str> = raw_command.split(" ").collect();
        let (keyword_raw, arguments_raw) = match command_parts.split_first() {
            Some((keyword_raw, arugments_raw)) => (keyword_raw, arugments_raw),
            None => return Command{
                keyword: String::from("INVALID"),
                arguments: Vec::new(),
            }
        };
        let keyword: String = String::from(*keyword_raw).to_uppercase();
        let arguments: Vec<String> = arguments_raw
            .iter()
            .map(|argument| String::from(*argument))
            .collect();
        return Command {
            keyword: String::from(keyword),
            arguments 
        }
    }

}

impl<'a> std::io::Read for POP3ServerSession<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.state != POP3ServerSessionStates::Done {
            // We should only process input if we're not done
            self.process_command();
        }
        let len: usize = std::cmp::min(buf.len(), self.output_buffer.len());
        buf[..len].copy_from_slice(&self.output_buffer[..len]);
        self.output_buffer.drain(..len);
        return Ok(len);
    }
}


impl<'a> std::io::Write for POP3ServerSession<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // TODO: Should add checks to make sure we 
        // enforce a maximum size for this buffer
        self.input_buffer.extend_from_slice(buf);
        return Ok(buf.len());
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // required by the std::io::Write type trait
        return Ok(());
    }
}
