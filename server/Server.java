
// Importing Required Classes
import java.net.Socket;
import java.net.ServerSocket;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class Server {

    private ServerSocket serverSocket;
    private Socket socket;
    private DataInputStream dataInputStream; 
    private DataOutputStream dataOutputStream;
    private BufferedReader bufferedReader;
    
    private int bitLength = 1024;
    private String USERNAME;
    private BigInteger USER_PublicKey_e;
    private BigInteger USER_PublicKey_N;
    private RSA rsa = new RSA();
    private SymmetricCrypto sym = new SymmetricCrypto();
    private Process process;
    
    Server(int PORT) throws Exception {

        // Starting Server Socket at Port PORT
        serverSocket = new ServerSocket(PORT);
        System.out.println("\nServer ON.");
        System.out.println("Waiting for Client request...");
        // Waiting for Client
        socket = serverSocket.accept();
        System.out.println("Client Request Received.");
        System.out.println("\nConnection Established\n");
        
        dataInputStream = new DataInputStream(socket.getInputStream());
        dataOutputStream = new DataOutputStream(socket.getOutputStream());

        // Step 1           - username and check
        USERNAME = dataInputStream.readUTF();
        System.out.println("username received: " + USERNAME);

        Path path = Paths.get("KNOWN_HOSTS.txt");
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        boolean isFound = false;
        for(int i=0; i<lines.size(); i=i+1) {
            if(lines.get(i).startsWith(USERNAME + ":")) {
                isFound = true;
                String line[] = lines.get(i).split(":");
                USER_PublicKey_e = new BigInteger(line[1].split("=")[1]);
                USER_PublicKey_N = new BigInteger(line[2].split("=")[1]);
            }
        }

        if(!isFound) {
            System.out.println("Username not Found!");

            dataOutputStream.writeUTF("not found");
            dataOutputStream.flush();
            System.out.println("ACK sent");

            socket.close();
            serverSocket.close();
            return;
        } else {
            System.out.println("Username Found!");
            // System.out.println(USER_PublicKey_e);
            // System.out.println(USER_PublicKey_N);

            dataOutputStream.writeUTF("found");
            dataOutputStream.flush();
            System.out.println("ACK sent");
        }

        // 1.1
        String keyFound = dataInputStream.readUTF();
        if(keyFound.equals("no")) {
            socket.close();
            serverSocket.close();
            return;
        }


        // Step 2           - p and g
        SecureRandom secureRandom = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength, secureRandom);
        BigInteger g = BigInteger.probablePrime(bitLength, secureRandom);

        dataOutputStream.writeUTF(p.toString());
        dataOutputStream.flush();
        System.out.println("p sent");
        
        dataOutputStream.writeUTF(g.toString());
        dataOutputStream.flush();
        System.out.println("g sent");

        // Step 3            - b
        BigInteger b = new BigInteger(bitLength, secureRandom);

        // Step 4            - A and B    /* B = g^b mod p */
        BigInteger B = g.modPow(b, p);
        dataOutputStream.writeUTF(B.toString());
        dataOutputStream.flush();
        System.out.println("B sent");

        BigInteger A = new BigInteger(dataInputStream.readUTF());
        System.out.println("A received");

        // Step 5              - S        /* s = A^b mod p */
        String SecretKey = A.modPow(b, p).toString();
        System.out.println("SecretKey is: " + SecretKey);

        // Step 6                - Encrypt n

        String n = new BigInteger(bitLength/10, secureRandom).toString();
        byte byt[] = n.getBytes();
        byte[] encryptedN = rsa.encryptMessage(byt, USER_PublicKey_e, USER_PublicKey_N);
        
        dataOutputStream.writeUTF(Integer.toString(encryptedN.length));
        dataOutputStream.flush();
        System.out.println("len sent");

        dataOutputStream.write(encryptedN, 0, encryptedN.length);
        dataOutputStream.flush();
        System.out.println("Encrypted n array sent: " + n);

        String encrytedNwithS = dataInputStream.readUTF();
        String decryptedNwithS = sym.decrypt(encrytedNwithS, SecretKey);
        System.out.println("decryptedNwithS received: " + decryptedNwithS);

        if(decryptedNwithS.equals(n)) {
            dataOutputStream.writeUTF("verified");
            dataOutputStream.flush();
            System.out.println("verified");
        } else {
            dataOutputStream.writeUTF("not verified");
            dataOutputStream.flush();
            System.out.println("not verified");

            socket.close();
            serverSocket.close();
            return;
        }

        String command = dataInputStream.readUTF();
        command = sym.decrypt(command, SecretKey);

        StringBuilder result;
        while(!command.equals("exit")) {

            boolean addUserCheckPass = false;
            try {
                String addUserCheck[] = command.split(" ");
                if(addUserCheck.length == 3 && addUserCheck[0].equals("add") && addUserCheck[1].equals("user")) {
                    // logic
                    addUserCheckPass = true;
                } else {
                    process = Runtime.getRuntime().exec(command);
                }
                System.out.println(command + " command ran");
            } catch (Exception e) {
                dataOutputStream.writeUTF(sym.encrypt("Command not found!\n", SecretKey));
                dataOutputStream.flush();
                
                command = dataInputStream.readUTF();
                command = sym.decrypt(command, SecretKey);
                continue;
            }

            if(addUserCheckPass) {
                result = new StringBuilder();

                String KEY[] = rsa.generateKey();
                result.append("\nBelow is your secret key for login into the SSH server.\nCopy and save it in a file with name <username>_KEY.txt\n\n");
                result.append("e=" + KEY[0]);
                result.append("\n");
                result.append("N=" + KEY[1]);
                result.append("\n");
                result.append("d=" + KEY[2]);
                result.append("\n");

                lines.add(command.split(" ")[2] + ":e=" + KEY[0] + ":N=" + KEY[1]);

                FileWriter fw = new FileWriter(new File("KNOWN_HOSTS.txt"));
                BufferedWriter out = new BufferedWriter(fw);
                for(String s : lines) {
                    out.write(s + "\n");
                }
                out.flush();
                out.close();
                fw.close();

                dataOutputStream.writeUTF(sym.encrypt(result.toString(), SecretKey));
                dataOutputStream.flush();
            } else  {
                bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                result = new StringBuilder();
                String output;
                
                output = bufferedReader.readLine();
                while(output != null) {
                    result.append(output + "\n");
                    output = bufferedReader.readLine();
                }
    
                dataOutputStream.writeUTF(sym.encrypt(result.toString(), SecretKey));
                dataOutputStream.flush();
                process.waitFor();
                process.exitValue();
                process.destroy();
            }
            command = dataInputStream.readUTF();
            command = sym.decrypt(command, SecretKey);
        }

        socket.close();
        serverSocket.close();
        dataInputStream.close();
        dataOutputStream.close();
        System.out.println("Connection Closed.");
    }

    public static void main(String[] args) throws Exception{
        int PORT = 22;
        Server server;
        
        while(true) {
            new Server(PORT);
            System.out.println(".");
        }
    }
}