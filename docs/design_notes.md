# Design Notes

```        API Calls    Callback
             --->         --->
Client bytes       Lib         Server Backend Implementation
             <---         <---
           API Responses  Callback Responses
```

The consumer of the library is responsible for implementing the networking aspects of client server communication as well as the client authorization, and backend email storage and retrieval. The library is responsible for translating POP3 requests into backend callbacks and then translating the responses of those backend callbacks into valid POP3 responses.

## List of user defined callbacks
