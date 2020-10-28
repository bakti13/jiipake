import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server {
    private final static String SERVERID = "Alice";
    private final static String SECRET_KEY = "secret_key";
    private final static int PORT = 1234;

    public static void main(String[] arg) {


        try (ServerSocket listener = new ServerSocket(PORT)) {
            System.out.println("The Server is running...");
            ExecutorService pool = Executors.newFixedThreadPool(20);
            while (true) {
                pool.execute(new ServerRun(listener.accept()));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class ServerRun implements Runnable {
        private final Socket socket;

        ServerRun(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            System.out.println("Connected: " + socket);

            BigInteger B, gB, x2, gx3, gx4, gx1, s1;
            BigInteger[] sigX3, sigX4, sigX4s;

            try {
                Scanner in = new Scanner(socket.getInputStream());
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                while (in.hasNextLine()) {
                    Exchange exchange = new Exchange();

                    /** Step 1.a: Alice/Server sends g^{x1}, g^{x2}
                     **/
                    /* Generate x1 and x2 */
                    BigInteger x1 = new BigInteger(160, new SecureRandom());
                    x2 = new BigInteger(160, new SecureRandom());

                    HashMap<String, Object> mapServer = exchange.roundOne(x1,x2,SERVERID);
                    // Generate gx1, gx2, ZKP1, ZKP2 Alice/Server
                    gx1 = new BigInteger((String) mapServer.get("gx1"));

                    // Sending gx1, gx2, ZKP1, ZKP2 Alice/Server to Bob/Client
                    out.println(exchange.toJson(mapServer));

                    System.out.println();
                    System.out.println("************************** Step 1 ****************************");
                    System.out.println("Alice/Server sends to Bob/Client: ");
                    System.out.println("g^{x1} = " + mapServer.get("gx1"));
                    System.out.println("g^{x2} = " + mapServer.get("gx2"));
                    System.out.println("KP{x1} = " + exchange.toJson(mapServer.get("ZKP1")));
                    System.out.println("KP{x2} = " + exchange.toJson(mapServer.get("ZKP2")));

                    /** Step 1.b Alice/Server Verifies ZKP from Bob/Client
                     **/
                    String message = in.nextLine();
                    // Mapping g^{x4}, KP{x3}, KP{x4} Bob/Client from response message
                    HashMap<String, Object> mapFromClient = exchange.fromJson(message);
                    gx3 = new BigInteger((String) mapFromClient.get("gx3"));
                    gx4 = new BigInteger((String) mapFromClient.get("gx4"));
                    sigX3 = exchange.toArray(mapFromClient.get("ZKP3"));
                    sigX4 = exchange.toArray(mapFromClient.get("ZKP4"));

                    System.out.println();
                    System.out.println("Alice/Server receive from Bob/Client: ");
                    System.out.println("g^{x3} = " + mapFromClient.get("gx3"));
                    System.out.println("g^{x4} = " + mapFromClient.get("gx4"));
                    System.out.println("KP{x3} = " + mapFromClient.get("ZKP3"));
                    System.out.println("KP{x4} = " + mapFromClient.get("ZKP4"));
                    System.out.println();


                    // Alice/Server verifies Bob/Client ZKPs and also check g^{x4} != 1
                    boolean validZKPs = exchange.cekZKP(gx3, gx4, sigX3, sigX4, SERVERID);

                    if (!validZKPs) {
                        System.out.println("g^{x4} shouldn't be 1 or invalid KP{x3,x4}");
                    } else {
                        System.out.println("Alice/Server checks g^{x4}!=1 = OK");
                        System.out.println("Alice/Server checks KP{x3}    = OK");
                        System.out.println("Alice/Server checks KP{x4}    = OK");
                        System.out.println();

                        /** Step 2.a : Alice/Server sending A*/
                        s1 = exchange.getSecretBigInt(SECRET_KEY);
                        HashMap<String, Object> map = exchange.roundTwo(gx1, gx3, gx4, x2, s1, SERVERID);

                        // Sending A, gA, KP{x2*s} Alice/Server to Bob/Client
                        exchange.delay(100);
                        out.println(exchange.toJson(map));

                        System.out.println("************************** Step 2 ****************************");
                        System.out.println("Alice/Server send to Bob/Client: ");
                        System.out.println("A        = " + map.get("A"));
                        System.out.println("KP{x2*s} = " + exchange.toJson(map.get("KP{x2*s}")));


                        /** Step 2.b Alice/Server checks KP{x4*s} from Alice/Server
                         **/
                        message = in.nextLine();
                        // Mapping B, gB, KP{x4*s} Bob/Client from response message
                        mapFromClient = exchange.fromJson(message);
                        gB = new BigInteger((String) mapFromClient.get("gB"));
                        B = new BigInteger((String) mapFromClient.get("B"));
                        sigX4s = exchange.toArray(mapFromClient.get("KP{x4*s}"));

                        System.out.println();
                        System.out.println("Alice/Server receive from Bob/Client: ");
                        System.out.println("B        = " + mapFromClient.get("B"));
                        System.out.println("KP{x4*s} = " + mapFromClient.get("KP{x4*s}"));
                        System.out.println();

                        // Alice/Server verifies Bob/Client ZKPs
                        validZKPs = exchange.chekZKPs(gB, B, sigX4s, SERVERID);
                        if (validZKPs) {
                            System.out.println("Alice/Server checks KP{x4*s}: OK");

                            /** Final Step: Generate Session Key (K) Alice/Server and sending to Bob/Client*/
                            BigInteger key = exchange.getSessionKeys(gx4, x2, B, s1);

                            Timestamp timestamp = new Timestamp(System.currentTimeMillis());

                            exchange.delay(200);
                            // sending key to Bob/Client
                            out.println(key.toString() + ";" + timestamp);


                            // get key from Bob/Client
                            message = in.nextLine();

                            System.out.println("\n*********************** Final Steps **************************");
                            System.out.println("Alice/Server computes a session key \t K=" + key.toString() + ";" + timestamp);
                            System.out.println("Bob/Client computes a session key \t\t K=" + message);
                            if (exchange.validateKey((message.split(";"))[0], key.toString())) {
                                System.out.println("Secret key is VALID");
                            } else {
                                System.out.println("Secret key is NOT VALID");
                            }
                            System.out.println("************************************************************");
                        } else {
                            System.out.println("Invalid ZK{x4*s}");
                            exchange.delay(200);
                            // sending key to Bob/Client
                            out.println("INVALID KEY");
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("Error:" + socket);
            } finally {
                try {
                    socket.close();
                } catch (IOException ignored) {
                }
                System.out.println("Closed: " + socket);
            }
        }
    }
}
