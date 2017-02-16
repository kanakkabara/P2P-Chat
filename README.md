# P2P-Chat
A Peer-to-Peer chatting application created in Python as part of the COMP3234 - Computer and Communication Networks course in HKU.

## Server
The room server keeps track of the chat rooms available, and the clients in each room. Each P2P client must regularly contact the room server to maintain the connection established initially (client must ping server every 20s to stay alive, or client will be disconnected).  

## Client
Each client acts as both a server (to other P2P clients for distributing messages along the network), and a client (receiver of messages from other P2P clients). Once a client is registered on the room server, it starts to look for a peer in the chat room it is in currently. Once it finds a suitable peer, it initiates a P2P Handshake. If accepted by the peer, both P2P clients are able to communicate with each other using Sockets. 

---

* Uses a new protocol created on top of TCP to demostrate creation and use of protocols.
* Uses sockets for bidirectional communication. 
* Uses threading to manage multiple peers on each P2P client.
* Uses a concept called flooding to distribute messages along the network. 
* Has logic to maintain integrity of network in case a peer leaves in order to maintain upkeep of Overlay network

