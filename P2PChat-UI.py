#!/usr/bin/python3

# Student name and No.: KABARA, Kanak Dipak; 3035164221
# Development platform: Ubuntu 16.04.1
# Python version: 3.5.2
# Version: 1.0


from tkinter import *
import sys
import socket
import _thread
import time

#
# Global variables
#

username = "" 							#Store the username that is defined by the user
clientStatus = "STARTED"					#The status of the client as dictated by the state diagram
chatHashID = ""							#The chat's hashID after joining a chat room, to be used for comparing with new hash ID on each KEEPALIVE request.
msgID = 0							#message ID of the last message sent
membersList = []						#List of information of all members in the chat room
backlinks = []
forwardlinks = []

#
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
	if userentry.get():					#If userentry is not empty
		if clientStatus != "JOINED":			#and they have not joined a chat room
			global username				#access the global variables . . 
			username = userentry.get()
			clientStatus = "NAMED"			# . . and store the new values
			CmdWin.insert(1.0, "\n[User] username: "+username)
			userentry.delete(0, END)
		else:
			CmdWin.insert(1.0, "\nCannot change username after joining a chatroom!")
	else:
		CmdWin.insert(1.0, "\nPlease enter username!")

def do_List():
	roomServerSocket.send(bytearray("L::\r\n", 'utf-8'))	#Send the L request
	response = roomServerSocket.recv(1024)			#Receive the response
	response = str(response.decode("utf-8"))		#Convert from bytearray to string
	if response[0] == 'G':					#Check if first char is G, signifying a successful request
		response = response[2:-4]			#Trim the G: and ::\r\n from the response
		if len(response) == 0:				#if response body is empty, no chat rooms exist
			CmdWin.insert(1.0, "\nNo active chatrooms")
		else:						#else, split the array using the : char, and output to CmdWin
			rooms = response.split(":")
			for room in rooms:
				CmdWin.insert(1.0, "\n\t"+room)
			CmdWin.insert(1.0, "\nHere are the active chat rooms:")	
	elif response[0] == 'F':				#If first char is F, it is an error.
		CmdWin.insert(1.0, "\nError fetching chatroom list!")

#ADAPTED FROM http://stackoverflow.com/questions/38680508/how-to-vstack-efficiently-a-sequence-of-large-numpy-array-chunks
def chunker(array, chunkSize):
    return (array[pos:pos + chunkSize] for pos in range(0, len(array), chunkSize))	

def do_Join():
	global clientStatus
	if userentry.get():
		if clientStatus == "NAMED" or clientStatus == "JOINED":
			global roomname 
			roomname = userentry.get()	
			roomServerSocket.send(bytearray("J:"+roomname+":"+username+":"+myIP+":"+myPort+"::\r\n", 'utf-8'))	
			response = roomServerSocket.recv(1024)
			response = str(response.decode("utf-8"))
			
			if response[0] == 'M':
				response = response[2:-4]
				members = response.split(":")

				global chatHashID 
				chatHashID = members[0]

				global membersList
				for group in chunker(members[1:], 3):
					membersList.append(group)
					CmdWin.insert(1.0, "\n"+str(group))
				clientStatus = "JOINED"
				
				_thread.start_new_thread (keepAliveProcedure, ())	#Start a new thread runnning the keepAliveProcedure
				_thread.start_new_thread (serverProcedure, ())		#Start a new thread runnning the server part of P2P
				findP2PPeer(membersList)				

			elif response[0] == 'F':
				CmdWin.insert(1.0, "\nAlready joined another chatroom!!")
			
		else:
			CmdWin.insert(1.0, "\nPlease set username first.")
	else:
		CmdWin.insert(1.0, "\nPlease enter room name!")	

def keepAliveProcedure():
	CmdWin.insert(1.0, "\nStarted KeepAlive Thread")
	while roomServerSocket:					#While the serversocket is intact, keep sending a join request every 20 seconds
		time.sleep(20)
		updateMembersList()				#Performs the JOIN request, also updates member list
	
def serverProcedure():
	sockfd = socket.socket()
	sockfd.bind( ('', int(myPort)) )
	while sockfd:
		sockfd.listen(5)
		conn, address = sockfd.accept()
		print ("Accepted connection from" + str(address))	
		response = conn.recv(1024)
		response = str(response.decode("utf-8"))
		
		if response[0] == 'P':
			response = response[2:-4]
			connectorInfo = response.split(":")
			connectorRoomname = connectorInfo[0]
			connectorUsername = connectorInfo[1]
			connectorIP = connectorInfo[2]
			connectorPort = connectorInfo[3]
			connectorMsgID = connectorInfo[4]
			global membersList			
			try:
				memberIndex = membersList.index(connectorInfo[1:4])
			except ValueError:
				if updateMembersList():
					try:
						memberIndex = membersList.index(connectorInfo[1:4])
					except ValueError:
						memberIndex = -1
						print("Unable to connect to " + str(address))
						conn.close()
				else:
					print("Unable to update member's list, so connection was rejected.")
					conn.close()				
			if memberIndex != -1:
				conn.send(bytearray("S:"+str(msgID)+"::\r\n", 'utf-8'))	
				#TODO create new thread to listen for incoming messages
				_thread.start_new_thread (handlePeer, (conn, ))					#Start a new thread runnning the server part of P2P
				
		else:
			conn.close()						#anything other than P or T must be failure so close
	
def handlePeer(conn):
	while conn:
		response = conn.recv(1024)
		response = str(response.decode("utf-8"))

def updateMembersList():
	roomServerSocket.send(bytearray("J:"+roomname+":"+username+":"+myIP+":"+myPort+"::\r\n", 'utf-8'))	
	response = roomServerSocket.recv(1024)
	response = str(response.decode("utf-8"))

	if response[0] == 'M':
		response = response[2:-4]
		members = response.split(":")
		global chatHashID
		if chatHashID != members[0]:
			global membersList				
			chatHashID = members[0]
			membersList = []
			for group in chunker(members[1:], 3):
				membersList.append(group)
				print("Member list updated!")
		return True
	elif response[0] == 'F':
		print("Error in performing JOIN request!")
		return False

def findP2PPeer(membersList):
	hashes = []
	for member in membersList:
		concat = ""
		for info in member:
			concat = concat + info
		hashes.append((member,sdbm_hash(concat)))
		if member[0] == username:
			myInfo = member
	hashes = sorted(hashes, key=lambda tup: tup[1])

	myHashID = sdbm_hash(username+myIP+myPort)
	start = (hashes.index((myInfo, myHashID)) + 1) % len(hashes)
	success = False
	while hashes[start][1] != myHashID:
		if hashes[start] in backlinks:
			start = (start + 1) % len(hashes) 
			continue
		else:
			peerSocket = socket.socket()
			str = "Found peer: " + hashes[start][0][0] + "["+hashes[start][0][1]+", "+hashes[start][0][2]+"]"
			print (str)
			
			peerSocket.connect((hashes[start][0][1], int(hashes[start][0][2])))
			if peerSocket:			
				if P2PHandshake(peerSocket):
					outStr = "Handshaken with " + hashes[start][0][0]
					print(outStr)
					success = True
					
		#			TODO add this connection to H’s socket list i.e. add forward link
		#			TODO update gList to indicate this link
					
					break
				else:
					start = (start + 1) % len(hashes) 
					continue
			else:
				start = (start + 1) % len(hashes) 
				continue
	if not success:
		return
		#TODO try again later
		
	
def P2PHandshake(peerSocket):
	peerSocket.send(bytearray("P:"+roomname+":"+username+":"+myIP+":"+myPort+":"+str(msgID)+"::\r\n", 'utf-8'))	
	response = peerSocket.recv(1024)
	response = str(response.decode("utf-8"))
	if response[0] == 'S':
		return True
	else:
		return False

def do_Send():
	CmdWin.insert(1.0, "\nPress Send")

def do_Quit():
	roomServerSocket.close()
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
Butt01 = Button(topmidframe, width='8', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='8', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='8', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='8', relief=RAISED, text="Send", command=do_Send)
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
		global roomServerSocket 
		global roomServerIP
		global roomServerPort
		global myPort
		global myIP
	
		roomServerSocket = socket.socket()
		roomServerIP = sys.argv[1]
		roomServerPort = sys.argv[2]
		myPort = sys.argv[3]
		myIP = socket.gethostbyname(socket.gethostname())
		
		roomServerSocket.connect((sys.argv[1], int(sys.argv[2])))

	win.mainloop()

if __name__ == "__main__":
	main()

