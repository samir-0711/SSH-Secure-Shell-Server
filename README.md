# SSH-Secure-Shell-Server

## Structure of project

<pre>
Project_Folder
    |_ client
          |_Client.java
          |_KEY.txt
          |_RSA.java
          |_SymmetricCrypto.java
    |_ server
          |_Server.java
          |_KNOWN_HOSTS.txt
          |_RSA.java
          |_SymmetricCrypto.java
</pre>

## Steps to run project

<pre>
<b>Step 1: </b>
First go to server folder.
Open terminal in that folder.
Compile Server.java file by running following command
 	  <b>javac Server.java</b>	
Run Server.java file with the following format.
 	  <b>java Server</b>


<b>Step 2: </b>
Now go to client folder.
Open terminal in that folder.
Compile Client.java file by running following command
 	  <b>javac Client.java</b>	
Run Client.java file with the following format.
          <b>java Client username@ipaddress</b> 
    Example:
 	  <b>java Client samir@127.0.0.1</b>	


If connection establish successfully and user is verified then you are logged in to the server.
Now you can access the server from your terminal.
</pre>

## Flowchart

![Flowchart of project](https://github.com/samir-0711/SSH-Secure-Shell-Server/blob/main/Flowchart.jpg)
