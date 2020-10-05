import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Scanner;

public class Client {
    private final static String CLIENTID = "Bob";
    private final static int PORT = 1234;

    public static void main(String[] args) {
        System.out.println("The Client is running...");

        BigInteger A, gA, x4, gx1, gx2, gx3, s2;
        BigInteger[] sigX1, sigX2, sigX2s;

        try (Socket socket = new Socket("localhost", PORT)) {
            Scanner in = new Scanner(socket.getInputStream());
            Scanner scanner = new Scanner(System.in);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            System.out.print("Check Secret Key : ");
            while (scanner.hasNextLine()) {
                String clientSecretKey = scanner.nextLine();
                out.println(clientSecretKey);

                Exchange exchange = new Exchange();


                /** Step 1.a: Bob/Client sends g^{x3}, g^{x4}
                 **/
                HashMap<String, Object> mapClient = exchange.roundOne(CLIENTID);
                /*Generate gx3, gx4, ZKP3, ZKP4 Bob/Client */
                x4 = (BigInteger) mapClient.get("x4");
                gx3 = (BigInteger) mapClient.get("gx3");

                /*Sending gx3, gx4, ZKP3, ZKP4 Bob/Client to Alice/Server*/
                out.println(exchange.toJson(mapClient));

                System.out.println();
                System.out.println("**************************Step 1****************************");
                System.out.println("Bob/Client sends to Alice/Server : ");
                System.out.println("g^{x3} = " + mapClient.get("gx3"));
                System.out.println("g^{x4} = " + mapClient.get("gx4"));
                System.out.println("KP{x3} = " + exchange.toJson(mapClient.get("ZKP3")));
                System.out.println("KP{x4} = " + exchange.toJson(mapClient.get("ZKP4")));

                /** Step 1.b Bob/Client Verifies ZKP from Alice/Server
                 **/
                String message = in.nextLine();
                // Mapping g^{x2}, KP{x1}, KP{x2} Alice/Server from response message
                HashMap<String, Object> mapFromServer = exchange.fromJson(message);
                gx1 = (BigInteger) mapFromServer.get("gx1");
                gx2 = (BigInteger) mapFromServer.get("gx2");
                sigX1 = exchange.toArray(mapFromServer.get("ZKP1"));
                sigX2 = exchange.toArray(mapFromServer.get("ZKP2"));

                // Bob/Client verifies Alice/Server ZKPs and also check g^{x2} != 1
                boolean validZKPs = exchange.cekZKP(gx1, gx2, sigX1, sigX2, CLIENTID);

                if (!validZKPs) {
                    System.out.println("g^{x2} shouldn't be 1 or invalid KP{x1,x2}");
                } else {
                    System.out.println("Bob/Client checks g^{x2}!=1 = OK");
                    System.out.println("Bob/Client checks KP{x1}    = OK");
                    System.out.println("Bob/Client checks KP{x2}    = OK");
                    System.out.println();

                    /* Step 2.a : Bob/Client sending B*/
                    s2 = new BigInteger(clientSecretKey.getBytes());
                    mapClient = exchange.roundTwo(gx3, gx1, gx2, x4, s2, CLIENTID);

                    /* Generate B, gB, KP{x4*s} Bob/Client
                     B = (BigInteger) mapClient.get("B");
                     gB = (BigInteger) mapClient.get("gB");
                     sigX4s = (BigInteger[]) mapClient.get("KP{x4*s}");*/

                    // Sending B, gB, KP{x4*s} Bob/Client to Alice/Server
                    out.println(exchange.toJson(mapClient));

                    System.out.println("**************************Step 2****************************");
                    System.out.println("Bob/Client sends to Alice/Server");
                    System.out.println("B        = " + mapClient.get("B"));
                    System.out.println("KP{x4*s} = " + exchange.toJson(mapClient.get("KP{x4*s}")));


                    /** Step 2.b Bob/Client checks KP{x2*s} from Alice/Server
                     **/
                    message = in.nextLine();
                    // Mapping A, gA, KP{x2*s} Alice/Server from response message
                    mapFromServer = exchange.fromJson(message);
                    A = (BigInteger) mapFromServer.get("A");
                    gA = (BigInteger) mapFromServer.get("gA");
                    sigX2s = exchange.toArray(mapFromServer.get("KP{x2*s}"));

                    // Bob/Client verifies Alice/Server ZKPs
                    validZKPs = exchange.chekZKPs(gA, A, sigX2s, CLIENTID);
                    if (validZKPs) {
                        System.out.println("Bob/Client checks KP{x2*s}: OK");

                        /** Final Step: Generate Session Key (K) Bob/Client and sending to Alice/Server **/
                        BigInteger key = exchange.getSessionKeys(gx2, x4, A, s2);

                        // get key from Alice/Server
                        message = in.nextLine();

                        Timestamp timestamp = new Timestamp(System.currentTimeMillis());

                        // sending key to Alice/Server
                        out.println(key.toString() + ";" + timestamp);

                        System.out.println("\n***********************Final Steps**************************");
                        System.out.println("Alice/Server computes a session key \t K=" + message);
                        System.out.println("Bob/Client computes a session key \t\t K=" + key.toString() + ";" + timestamp);
                        if (exchange.validateKey(message, key.toString())) {
                            System.out.println("Secret key " + clientSecretKey + " is VALID");
                        } else {
                            System.out.println("Secret key " + clientSecretKey + " is NOT VALID");
                        }
                        System.out.println("************************************************************");
                    } else {
                        System.out.println("Invalid ZK{x2*s}");
                    }
                }
                System.out.print("\nCheck Secret Key : ");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
