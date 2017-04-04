#!/usr/bin/python3

# Student name and No.: KABARA, Kanak Dipak; 3035164221
# Development platform: Ubuntu 16.04.1
# Python version: 3.5.2
# Version: 2.0

#TODO test cases of changing name at any time in state cycle
#TODO test cases of pressing join at any time in state cycle

from tkinter import *
import sys
import socket
import _thread
import threading
import time
import datetime

#
# Global variables
#

username = "" 							#Store the username that is defined by the user
clientStatus = "STARTED"					#The status of the client as dictated by the state diagram
chatHashID = ""							#The chat's hashID after joining a chat room, to be used for comparing with new hash ID on each KEEPALIVE request.
msgID = 0							#message ID of the last message sent
myRoom = ""							#Name of the room currently joined
membersList = []						#List of information of all members in the chat room
backlinks = []							#Array of tuples containing information of the backward linked clients, along with the socket to contact them
forwardLink = ()						#Tuple containing information of the forward linked client, along with the socket to contact them
messages = []							#Array storing the messages received (the hash ID of the sender, along with the msgID)
hashes = []							#Array of tuples containing information of members, along with their hash ID
lock = threading.Lock()						#mutex lock for messages array as it is shared between threads who append data to array; we dont want them to append together = 
								#could lead to duplication of messages if two threads i.e. two clients try to forward the same message at the same time 

# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address), 
# and str(Port) to form the input to this hash function
#
def sdbm_hash(instr):
	hash = 0
	for c in instr:
		hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff


#
# Functions to handle user input
#

def do_User():
	global clientStatus
	if userentry.get():									#If userentry is not empty
		if clientStatus != "JOINED" and clientStatus != "CONNECTED":			#and they have not joined a chat room
			global username								#access the global variables . . 
			username = userentry.get()
			clientStatus = "NAMED"							# . . and store the new values
			CmdWin.insert(1.0, "\n[User] username: "+username)
			userentry.delete(0, END)
		else:
			CmdWin.insert(1.0, "\nCannot change username after joining a chatroom!")
	else:
		CmdWin.insert(1.0, "\nPlease enter username!")

def do_List():
	msg = "L::\r\n"
	try:
		roomServerSocket.send(msg.encode("ascii"))
		response = roomServerSocket.recv(1024)							#Receive the response
		response = str(response.decode("ascii"))						#Convert from bytearray to string
		if response:
			if response[0] == 'G':									#Check if first char is G, signifying a successful request
				response = response[2:-4]							#Trim the G: and ::\r\n from the response
				if len(response) == 0:								#if response body is empty, no chat rooms exist
					CmdWin.insert(1.0, "\nNo active chatrooms")
				else:										#else, split the array using the : char, and output to CmdWin
					rooms = response.split(":")
					for room in rooms:
						CmdWin.insert(1.0, "\n\t"+room)
					CmdWin.insert(1.0, "\nHere are the active chat rooms:")	
			elif response[0] == 'F':
				response = response[2:-4]								#If first char is F, it is an error.
				CmdWin.insert(1.0, "\nError fetching chatroom list: "+response)
		else:
			raise socket.error("IndexError due to broken socket")	
	except socket.error as err:
		print(str(err))
		CmdWin.insert(1.0, "\nConnection to Room Server broken, reconnecting;")
		roomServerSocket.close()	
		_thread.start_new_thread (roomServerConnect, (do_List, ))		#Start a new thread to make a connection with the room server

#ADAPTED FROM http://stackoverflow.com/questions/38680508/how-to-vstack-efficiently-a-sequence-of-large-numpy-array-chunks
def chunker(array, chunkSize):
    return (array[pos:pos + chunkSize] for pos in range(0, len(array), chunkSize))	

def do_Join():
	global clientStatus
	try:
		if userentry.get():
			if username != "":
				if not (clientStatus == "JOINED" or clientStatus == "CONNECTED"):
					global roomname 
					roomname = userentry.get()
					msg = "J:"+roomname+":"+username+":"+myIP+":"+myPort+"::\r\n"
					roomServerSocket.send(msg.encode("ascii"))
					response = roomServerSocket.recv(1024)
					response = str(response.decode("ascii"))
					
					if response:
						if response[0] == 'M':	
							response = response[2:-4]				#Trim the M: and ::\r\n from the response
							members = response.split(":")				#Split the array using the : char

							global chatHashID 
							chatHashID = members[0]					#Store chathash to check if member list changed later on

							global membersList
							CmdWin.insert(1.0, "\nJoined chat room: "+roomname)
							for group in chunker(members[1:], 3):			#Break array into array of arrays, each containing the username, IP and port for contacting
								membersList.append(group)
								CmdWin.insert(1.0, "\n\t"+str(group))
							CmdWin.insert(1.0, "\nHere are the members:")	
							clientStatus = "JOINED"					#Status is now JOINED
							userentry.delete(0, END)
					
							global myRoom
							myRoom = roomname					#Store roomname joined
							_thread.start_new_thread (keepAliveProcedure, ())	#Start a new thread runnning the keepAliveProcedure
							_thread.start_new_thread (serverProcedure, ())		#Start a new thread runnning the server part of P2P
							findP2PPeer(membersList)				#Find a peer to connect via
						elif response[0] == 'F':
							response = response[2:-4]
							CmdWin.insert(1.0, "\nError performing JOIN req: "+response)
					else:
						raise socket.error("IndexError due to broken socket")
				else:
					CmdWin.insert(1.0, "\nAlready joined/connected to another chatroom!!")
			else:
				CmdWin.insert(1.0, "\nPlease set username first.")
		else:
			CmdWin.insert(1.0, "\nPlease enter room name!")
	except socket.error as err:
		print(str(err))
		CmdWin.insert(1.0, "\nConnection to Room Server broken, reconnecting;")
		roomServerSocket.close()	
		_thread.start_new_thread (roomServerConnect, (do_Join, ))		#Start a new thread to make a connection with the room server


def keepAliveProcedure():
	CmdWin.insert(1.0, "\nStarted KeepAlive Thread")
	while roomServerSocket:						#While the serversocket is intact, keep sending a join request . . . 
		time.sleep(20)						# . . . every 20 seconds
		updateMembersList("Keep Alive")				#Performs the JOIN request, also updates member list
		if clientStatus == "JOINED" or not forwardLink:		#If client is still not CONNECTED, i.e. still in JOINED state, look for a peer
			global membersList
			findP2PPeer(membersList)
	
def serverProcedure():
	sockfd = socket.socket()
	sockfd.bind( ('', int(myPort)) )				#Create a socket on current IP, with port set as listening port
	while sockfd:
		sockfd.listen(5)					
		conn, address = sockfd.accept()
		print ("Accepted connection from" + str(address))	
		response = conn.recv(1024)				#Wait for P2P handshake message
		response = str(response.decode("ascii"))
		
		if response:
			if response[0] == 'P':					#If peer initiated P2P handshake . . 
				response = response[2:-4]			#Collect all info about the handshaker
				connectorInfo = response.split(":")
				connectorRoomname = connectorInfo[0]
				connectorUsername = connectorInfo[1]
				connectorIP = connectorInfo[2]
				connectorPort = connectorInfo[3]
				connectorMsgID = connectorInfo[4]
				global membersList			
				try:						
					memberIndex = membersList.index(connectorInfo[1:4])				#check if initiating peer is in current member list
				except ValueError:									#error thrown if can't find . . 
					if updateMembersList("Server Procedure"):					# . . so get updated memberlist from sever
						try:
							memberIndex = membersList.index(connectorInfo[1:4])		#retry looking for initiating peer 
						except ValueError:							#error thrown if can't find . . 
							memberIndex = -1						# . . so it is some unknown peer, reject connection
							print("Unable to connect to " + str(address))
							conn.close()
					else:
						print("Unable to update member's list, so connection was rejected.")
						conn.close()					
				if memberIndex != -1:									#If member was found . . 
					msg = "S:"+str(msgID)+"::\r\n"
					conn.send(msg.encode("ascii"))							# . . reply with a successful message, completing the handshake
					concat = connectorUsername + connectorIP + connectorPort
					backlinks.append(((connectorInfo[1:4],sdbm_hash(concat)), conn))		#add information of new connection to backlinks array
					global clientStatus
					clientStatus = "CONNECTED"							#Since client now has backlink, it is in CONNECTED state
					_thread.start_new_thread (handlePeer, ("Backward", conn, ))			#Start a new thread to accept messages from peer
					CmdWin.insert(1.0, "\n" + connectorUsername + " has linked to me")
			else:
				conn.close()
		else:
			conn.close()										#anything other than P or T must be failure so close
	
def handlePeer(linkType, conn):
	while conn:												#While the connection is active
		response = conn.recv(1024)									#Receive text messages
		response = str(response.decode("ascii"))
		
		if response:											#To check if the recv has not been un-blocked due to broken socket
			if response[0] == 'T':									#T stands for text message, so successful message recvd
				response = response[2:-4]
				msgInfo = response.split(":")
				room = msgInfo[0]								#Get room name of message
			
				if room == myRoom:								#if my room, collect all info from message
					originHashID = msgInfo[1]
					originUsername = msgInfo[2]
					originMsgID = msgInfo[3]
					originMsgLen = msgInfo[4]
					originMsg = response[-(int(originMsgLen)):]				#Get the last n chars from response, where n = len of message
					
					lock.acquire()								#acquire the lock since this is the critical section where messages array is modified
					global messages
					if (originHashID, originMsgID) not in messages:				#If message has not been seen before, add it to msg window and store to messages array
						MsgWin.insert(1.0, "\n["+originUsername+"] "+originMsg)
						messages.append((originHashID, originMsgID))
						lock.release()									#Release lock since message has been appended
						echoMessage(originHashID, originUsername, originMsg, originMsgID)		#Echo to all backlinks + forward link
						arr = [member for member in hashes if str(member[1]) == str(originHashID) ] 
						if not arr:							#If the arr doesnt contain the member that is the origin sender, update members list
							print("Not found hash", str(arr))
							updateMembersList("Peer Handler")
					else:
						print("Recvd repeated message")
						lock.release()							#Release lock, since we have already seen this message so no need to append
				else:
					print("Recvd message from wrong chat room")
		else:
			break											#Socket broken, look for new forward if forward gone, update backlinks otherwise
	
	if linkType == "Forward":					#If a forward link has been broken, the client is DISCONNECTED, and put back in JOINED state
		updateMembersList("Peer Quit")				#Update members list, reset forward link, look for new P2P peer
		global forwardLink
		forwardLink = ()
		global clientStatus
		clientStatus = "JOINED"
		findP2PPeer(membersList)
	else:								#If back link broken, remove the link from backlinks array
		global backlinks
		for back in backlinks:
			if back[1] == conn:
				backlinks.remove(back)
				break
		
def updateMembersList(*src):
	msg = "J:"+roomname+":"+username+":"+myIP+":"+myPort+"::\r\n"
	try:
		roomServerSocket.send(msg.encode("ascii"))
		response = roomServerSocket.recv(1024)
		response = str(response.decode("ascii"))
		if response:
			if response[0] == 'M':									#M stands for member list, so successful JOIN request
				now = datetime.datetime.now()							#Time info for debugging purposes [to check if KEEPALIVE running every 20 seconds]
				print(src, "Performing JOIN at", now.strftime("%Y-%m-%d %H:%M:%S"))
				response = response[2:-4]
				members = response.split(":")
				global chatHashID
				if chatHashID != members[0]:							#If hashID changed . . 
					global membersList							# . . New members in room, update members list accordingly
					chatHashID = members[0]
					membersList = []
					for group in chunker(members[1:], 3):
						membersList.append(group)
					print("Member list updated!")
					calculateHashes(membersList)						#recalc the hashes
				return True
			elif response[0] == 'F':								#F stands for failure, throw error
				response = response[2:-4]
				CmdWin.insert(1.0, "\nError performing JOIN req: "+response)
				return False
		else:
			return False
	except:
		CmdWin.insert(1.0, "\nConnection to Room Server broken, reconnecting;")
		roomServerSocket.close()	
		_thread.start_new_thread (roomServerConnect, (updateMembersList, ))		#Start a new thread to make a connection with the room server
		
def calculateHashes(membersList):
	global hashes 
	hashes = []
	for member in membersList:
		concat = ""									#concatenate the member info
		for info in member:
			concat = concat + info
		hashes.append((member,sdbm_hash(concat)))					#and add the member info, along with their hash to the hashes array
		if member[0] == username:							
			myInfo = member
	hashes = sorted(hashes, key=lambda tup: tup[1])						#sort the array using the hash ID as the key
	return myInfo

def findP2PPeer(membersList):
	myInfo = calculateHashes(membersList)
	global hashes
	global myHashID
	
	myHashID = sdbm_hash(username+myIP+myPort)									#calc my hash id by concating all info
	start = (hashes.index((myInfo, myHashID)) + 1) % len(hashes)							#find the index to start searching for peer

	while hashes[start][1] != myHashID:										#Loop until you loop back to yourself
		if [item for item in backlinks if item[0] == hashes[start]]:						#if the hashID exists in backlinks array, goto next index		
			start = (start + 1) % len(hashes) 
			continue
		else:
			peerSocket = socket.socket()
			try:												#if not, open a socket and try to connect 
				peerSocket.connect((hashes[start][0][1], int(hashes[start][0][2])))
			except:
				print("Cannot make peer socket connection with ["+hashes[start][0][1]+"], trying another peer")
				start = (start + 1) % len(hashes) 
				continue
			if peerSocket:											#if connection accepted
				if P2PHandshake(peerSocket):								#init P2P handshake
					CmdWin.insert(1.0, "\nConnected via - " + hashes[start][0][0])			#If success, store connection
					global clientStatus
					clientStatus = "CONNECTED"							#Since forward link created, cliennt is now connected
					global forwardLink				
					forwardLink = (hashes[start], peerSocket)					#Store peer info, hashID and the socket to contact peer
					_thread.start_new_thread (handlePeer, ("Forward", peerSocket, ))		#Start a new thread to listen for messages from client
					break
				else:
					peerSocket.close()								#P2P failed, close connection and try again at next index
					start = (start + 1) % len(hashes) 
					continue
			else:
				peerSocket.close()									#Peer rejected connection request, try at next index
				start = (start + 1) % len(hashes) 
				continue		
	if clientStatus != "CONNECTED":
		print("Unable to find forward connection")
		#No need to reschedule, as call to findP2PPeer included in KEEPALIVE procedure, so if client is still in JOINED state after 20 seconds, KEEPALIVE proc will init this procedure. 
	
def P2PHandshake(peerSocket):
	msg = "P:"+roomname+":"+username+":"+myIP+":"+myPort+":"+str(msgID)+"::\r\n"
	try:
		peerSocket.send(msg.encode("ascii")) 
		response = peerSocket.recv(1024)
		response = str(response.decode("ascii"))
		if response:
			if response[0] == 'S':					#If peer responds with S, it is a success, so return True else false
				return True
			else:
				return False
	except:
		return False

def do_Send():
	if userentry.get():
		if clientStatus == "JOINED" or clientStatus == "CONNECTED":		#Only if client is JOINED or CONNECTED do we try and send the message
			global msgID
			msgID += 1
			MsgWin.insert(1.0, "\n["+username+"] "+userentry.get())
			echoMessage(myHashID, username, userentry.get(), msgID)		#Call echoMessage with my details. 
		else:
			CmdWin.insert(1.0, "\nNot joined any chat!")
	userentry.delete(0, END)	

def echoMessage(originHashID, username, message, msgID):
	msg = "T:"+roomname+":"+str(originHashID)+":"+username+":"+str(msgID)+":"+str(len(message))+":"+message+"::\r\n"
	if forwardLink:									#If a forward link exists . . 
		if str(forwardLink[0][1]) != str(originHashID):				# . . and it is not the origin sender
			forwardLink[1].send(msg.encode("ascii"))		#Send message and add to sentTo array
			sentTo.append(str(forwardLink[0][1]))
			
	for back in backlinks:								#For all backlinked peers
		if str(back[0][1]) != str(originHashID):				#If they are not the origin sender
			back[1].send(msg.encode("ascii"))			#Send the message and add to the sentTo array
			sentTo.append(str(back[0][1]))
	#CmdWin.insert(1.0, "\nSent to " + str(sentTo))

def do_Quit():
	#Close all sockets - to the room server, to forward link if any, and to all the backlinked clients.
	if roomServerSocket:
		roomServerSocket.close()
		print("Quit: Closed Socket to Room Server")
	if forwardLink:
		forwardLink[1].close()
		print("Quit: Closed Socket to Forward link - ", forwardLink[0][0][0])
	for back in backlinks:
		back[1].close()
		print("Quit: Closed Socket to Backward link - ", back[0][0][0])
	sys.exit(0)

#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='8', relief=RAISED, text="User", state=DISABLED, command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='8', relief=RAISED, text="List", state=DISABLED, command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='8', relief=RAISED, text="Join", state=DISABLED, command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='8', relief=RAISED, text="Send", state=DISABLED, command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='8', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)

def main():
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)
	else:
		global roomServerIP
		global roomServerPort
		global myPort

		roomServerIP = sys.argv[1]
		roomServerPort = sys.argv[2]
		myPort = sys.argv[3]
		_thread.start_new_thread (roomServerConnect, (do_User, ))		#Start a new thread runnning the server part of P2P
	win.mainloop()
	
def roomServerConnect(callback):	
	global roomServerSocket 
	global roomServerIP
	global roomServerPort
	global myIP
	
	Butt01['state'] = 'disabled'
	Butt02['state'] = 'disabled'
	Butt03['state'] = 'disabled'
	Butt04['state'] = 'disabled'
	
	#myIP = socket.gethostbyname(socket.gethostname())
	i=0
	while True:
		i = i+1
		print("Trying to connect to Room Server")
		try:
			roomServerSocket = socket.socket()
			roomServerSocket.connect((roomServerIP, int(roomServerPort)))
			myIP = roomServerSocket.getsockname()[0]
			CmdWin.insert(1.0, "\nConnected to Room Server!")
			Butt01['state'] = 'normal'
			Butt02['state'] = 'normal'
			Butt03['state'] = 'normal'
			Butt04['state'] = 'normal'
			break		
		except ConnectionRefusedError:
			roomServerSocket.close()
			CmdWin.delete(2.0, 3.0)
			CmdWin.insert(1.0, "\nCannot contact Room Server, will try again in some time (" + str(i) +")")
			time.sleep(5)
	callback()

if __name__ == "__main__":
	main()
