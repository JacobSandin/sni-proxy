
Just something im working on right now to teach myself rust. Sometimes I do stream https://www.youtube.com/channel/UCHjoHMIwzAbOYIc5_DWADNQ.  


Added MIO polling  
Added normal HTTP  
Added certificate and rustls HTTPS  
Added SNI resolver using rustls  
Added to GIT  
Added logging and alot of trace with log and env_logger  
Commented main.rs  
Added comments for macros, connection_source.
Added Macros for errorhandling
Rewrote functions to be not as long, and code is now easier on the eyes.
Done: Parse request from client and forward to forward host  
Done: Make a request of forward host and return responce to client  


1. TODO: Start using dotenv, as we are starting to handling sensitive data.  
2. TODO: Make a queue to send and receive instead of a single vec for each direction. Look at VecDeque  
TODO: Find a way not to use regex to get dnsnames from DNSNameRef..
TODO: Make tests  
TODO: Write information to README file  
TODO: Remake trace to only log, headers and not body. Spliting at \r\n\r\n  
TODO: Look att dbImport of certs and hostnames.
TODO: Look att cashing DB config when goten for faster access.  
  
  