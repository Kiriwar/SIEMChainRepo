import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Simple alert receiver to monitor incoming alerts
 */
public class AlertReceiver {
    
    private static final int PORT = 9999;
    
    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(PORT);
        
        System.out.println("\n🔔 Alert Monitoring System Started");
        System.out.println("Listening on port " + PORT);
        System.out.println("Waiting for alerts...\n");
        
        while (true) {
            Socket clientSocket = serverSocket.accept();
            
            // Handle alert in new thread
            new Thread(() -> {
                try {
                    handleAlert(clientSocket);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }
    
    private static void handleAlert(Socket socket) throws IOException {
        BufferedReader in = new BufferedReader(
            new InputStreamReader(socket.getInputStream())
        );
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        
        // Read the alert
        StringBuilder alertData = new StringBuilder();
        String line;
        int contentLength = 0;
        
        // Read headers
        while ((line = in.readLine()) != null && !line.isEmpty()) {
            if (line.startsWith("Content-Length:")) {
                contentLength = Integer.parseInt(line.substring(15).trim());
            }
        }
        
        // Read body
        if (contentLength > 0) {
            char[] buffer = new char[contentLength];
            in.read(buffer, 0, contentLength);
            alertData.append(buffer);
        }
        
        // Display alert
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        
        System.out.println("\n" + "=".repeat(60));
        System.out.println("🚨 ALERT RECEIVED");
        System.out.println("=".repeat(60));
        System.out.println("Time: " + timestamp);
        System.out.println("From: " + socket.getInetAddress().getHostAddress());
        System.out.println("\nAlert Content:");
        System.out.println(alertData.toString());
        System.out.println("=".repeat(60) + "\n");
        
        // Send response
        out.println("HTTP/1.1 200 OK");
        out.println("Content-Type: application/json");
        out.println();
        out.println("{\"status\":\"received\"}");
        
        socket.close();
    }
}