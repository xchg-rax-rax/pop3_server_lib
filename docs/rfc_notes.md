# RFC Notes

## RFC-1939

### 1 Introduction

- POP3 is a simple protocol to allow clients not hosting an SMTP server to download email from a server which is hosting one.
- POP3 only really allows for mail to be downloaded and deleted, not manipulated

### 2. A short digression

- POP3 is not responsible for allowing clients to send mail (this is done using SMTP and SMTP relays)

### 3. Basic Operation

- POP3 runs on TCP port 110
- POP3 server sends a greeting when the client successfully connects
- The client sends commands to the server
- The server reply with response
- This continues until the connection is closed or aborted

- POP3 commands are case insensitive keywords
- They can optionally be followed by one or more arguments
- Commands are terminated by CRLF pair
- Keywords and args consist of printable ascii characters
- Keywords and args are separated by a single space
- Keywords are 3 or 4 characters long 
- Args are no more than 40 characters long

- Reposes are made of status indicator and keyword
- May be followed by additional information
- Responses are terminated by CRLF pair
- May be upto 512 characters long including the CRLF
- Status indicators (case sensitive):
    - `+OK`
    - `-ERR`
- Some responses are multi-line
- All lines are terminated by CRLF
- When all lines are sent a final terminating line is sent
    - `.<CRLF>`
- That the fuck does this mean?
> If any line of the multi-line response begins with the termination octet, the line is "byte-stuffed" by pre-pending the termination octet to that line of the response.
> Hence a multi-line response is terminated with the five octets"CRLF.CRLF".
> When examining a multi-line response, the client checks to see if the line begins with the termination octet.
> If so and if octets other than CRLF follow, the first octet of the line (the termination octet) is stripped away.
> If so and if CRLF immediately follows the termination character, then the response from the POP server is ended and the line containing ".CRLF" is not considered part of the multi-line response.

- POP3 session has a number of states
    - `AUTHORIZATION` - state after initial greeting is sent by server
    - `TRANSACTION` - state after authorization has occurred
    - `UPDATE` - state after the client has sent `QUIT` command
 
- The server responds to any unrecognised or unimplemented or invalid command by sending a negative status
