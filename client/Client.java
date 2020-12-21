// Importing Required Classes
import java.net.Socket;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class Client {
    
    private Socket socket;
    private DataInputStream dataInputStream; 
    private DataOutputStream dataOutputStream; 
    private BufferedReader bufferedReader;

    private int bitLength = 1024;
    private BigInteger USER_PublicKey_N;
    private BigInteger USER_PublicKey_d;
    private RSA rsa = new RSA();
    private SymmetricCrypto sym = new SymmetricCrypto();

    Client(String IP, String USERNAME) throws Exception {

        try {
            socket = new Socket(IP, 22);
        } catch (Exception e) {
            System.out.println(e);
            System.out.println("Connection Failed!!! Check the IP Address of the server...");
            return;
        }
        System.out.println("\nConnection Established\nVerifying User...");

        dataInputStream = new DataInputStream(socket.getInputStream());
        dataOutputStream = new DataOutputStream(socket.getOutputStream());
        bufferedReader = new BufferedReader(new InputStreamReader(System.in));

        // Step 1 - username
        dataOutputStream.writeUTF(USERNAME);
        dataOutputStream.flush();

        String ACK = dataInputStream.readUTF();
        if (ACK.equals("not found")) {
            System.out.println("Username not Found!");
            return;
        } else {
            Path path = Paths.get(USERNAME + "_KEY.txt");
            List<String> lines;
            try {
                lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            } catch (Exception e) {
                System.out.println("Error: " + e);
                System.out.println("\nNo Key Found!!!\n");

                // 1.1
                dataOutputStream.writeUTF("no");
                dataOutputStream.flush();
                return;
            }
            // 1.1
            dataOutputStream.writeUTF("yes");
            dataOutputStream.flush();

            new BigInteger(lines.get(0).split("=")[1]);
            USER_PublicKey_N = new BigInteger(lines.get(1).split("=")[1]);
            USER_PublicKey_d = new BigInteger(lines.get(2).split("=")[1]);
        }

        // Step 2       - p and g
        BigInteger p = new BigInteger(dataInputStream.readUTF());

        BigInteger g = new BigInteger(dataInputStream.readUTF());

        // Step 3       - a
        SecureRandom secureRandom = new SecureRandom();
        BigInteger a = BigInteger.probablePrime(bitLength, secureRandom);

        // Step 4       - A and B       /* A = g^a mod p */
        BigInteger A = g.modPow(a, p);
        BigInteger B = new BigInteger(dataInputStream.readUTF());
        
        dataOutputStream.writeUTF(A.toString());
        dataOutputStream.flush();

        // Step 5       - S            /* s = B^a mod p */
        String SecretKey = B.modPow(a, p).toString();

        // Step 6                - Encrypted n received and decrpt and e

        String len = dataInputStream.readUTF();

        byte[] encryptedN = new byte[Integer.parseInt(len)];
        dataInputStream.read(encryptedN, 0, Integer.parseInt(len));
        
        byte[] decryptedN = rsa.decryptMessage(encryptedN, USER_PublicKey_d, USER_PublicKey_N);

        dataOutputStream.writeUTF(sym.encrypt(new String(decryptedN), SecretKey));
        dataOutputStream.flush();

        ACK = dataInputStream.readUTF();
        if(ACK.equals("not verified")) {
            System.out.println("Permission Denied!");
            return;
        } else {
            System.out.println("User Verified");
        }

        System.out.println("You are login to the Server...");
        System.out.println("Type \"exit\" to logout and exit the Server");
        System.out.print(USERNAME + "@ ");


        bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        String command = bufferedReader.readLine();
        while(!command.equals("exit")) {
            
            command = sym.encrypt(command, SecretKey);
            dataOutputStream.writeUTF(command);
            dataOutputStream.flush();
            
            String result = sym.decrypt(dataInputStream.readUTF(), SecretKey);
            System.out.print(result);
            System.out.print(USERNAME + "@ ");

            command = bufferedReader.readLine();
        }
        command = sym.encrypt(command, SecretKey);
        dataOutputStream.writeUTF(command);
        dataOutputStream.flush();
        
        socket.close();
        dataInputStream.close();
        dataOutputStream.close();
        System.out.println("Connection Closed.");
    }

    public static void main(String[] args) throws Exception {
        String username, ip;
        if(args.length == 0) {
            System.out.println("Please enter the username and ip of the server...");
            System.out.println("Like this: username@ipaddress");
            return;
        } else {
            String input[] = args[0].split("@");
            if(input.length != 2) {
                System.out.println("Invalid username and ip address format!");
                System.out.println("Like this: username@ipaddress");
                return;
            }
            else {
                username = input[0];
                ip = input[1];
            }
        }
        new Client(ip, username);
    }
}