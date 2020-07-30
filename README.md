
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
Done: Look att dbImport of certs and hostnames.
Done: Start using dotenv, as we are starting to handling sensitive data.  

TODO: Create a interface for plugins, for certs and cache.  
TODO: Create plugin for creating new certs, and reloading cached ones.
TODO: Make redundant, im thinking it should have connection tests and then  
        be able to move IP depending on connection with other hosts, and  
        its counter part.  
TODO: Get a http-headers parser or make one for what we need  
TODO: Rotate event numbers in MIO main loop  
TODO: Investigate, paralell mio loops for server and backend requests.  
TODO: Find a way not to use regex to get dnsnames from DNSNameRef..  
TODO: Make tests  
TODO: Write information to README file  
TODO: Look att cashing DB config when goten for faster access.  
TODO: Remake trace to only log, headers and not body. Spliting at \r\n\r\n  
  
  
WONTDO-now: Make a queue to send and receive instead of a single vec for each direction. Look at VecDeque  
This just did not work, tried and it was a mess, I tried rewrite it a few times. And then I figured  
that when we start wit cashing and decoding we will not use it anyways. However, there might be a need  
if handling large file downloads, idk.
..
..
