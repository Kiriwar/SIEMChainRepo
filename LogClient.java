import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;

/**
 * Complete Client-side application to send log packets to the server
 * Each packet can contain 1 or more logs
 */
public class LogClient {
    
    private String serverUrl;
    private static final int DEFAULT_PORT = 8080;
    
    public LogClient(String serverHost, int serverPort) {
        this.serverUrl = "http://" + serverHost + ":" + serverPort;
    }
    
    public LogClient(String serverHost) {
        this(serverHost, DEFAULT_PORT);
    }
    
    /**
     * Send a single log to the server
     */
    public String sendSingleLog(String logContent) throws IOException {
        return sendPacket(logContent);
    }
    
    /**
     * Send multiple logs as a packet (array)
     */
    public String sendMultipleLogs(List<String> logs) throws IOException {
        StringBuilder packet = new StringBuilder();
        packet.append("[\n");
        
        for (int i = 0; i < logs.size(); i++) {
            packet.append("  ").append(logs.get(i));
            if (i < logs.size() - 1) {
                packet.append(",");
            }
            packet.append("\n");
        }
        
        packet.append("]");
        
        return sendPacket(packet.toString());
    }
    
    /**
     * Send a packet to the server
     */
    private String sendPacket(String packetContent) throws IOException {
        URL url = new URL(serverUrl + "/upload");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        
        // Send packet
        try (OutputStream os = conn.getOutputStream()) {
            os.write(packetContent.getBytes());
            os.flush();
        }
        
        // Read response
        int responseCode = conn.getResponseCode();
        BufferedReader in = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        String inputLine;
        StringBuilder response = new StringBuilder();
        
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        
        System.out.println("Response: " + response.toString());
        
        return response.toString();
    }
    
    /**
     * Send logs from a file
     */
    public String sendLogsFromFile(String filePath) throws IOException {
        System.out.println("\nSending file: " + filePath);
        String content = new String(Files.readAllBytes(Paths.get(filePath)));
        return sendPacket(content);
    }
    
    /**
     * Get server status
     */
    public String getStatus() throws IOException {
        URL url = new URL(serverUrl + "/status");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        BufferedReader in = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        String inputLine;
        StringBuilder response = new StringBuilder();
        
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine).append("\n");
        }
        in.close();
        
        return response.toString();
    }
    
    /**
     * Force server to flush current logs
     */
    public String flushServer() throws IOException {
        URL url = new URL(serverUrl + "/flush");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        
        BufferedReader in = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        String inputLine;
        StringBuilder response = new StringBuilder();
        
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        
        return response.toString();
    }
    
    /**
     * Generate sample logs for testing
     */
    public static List<String> generateSampleLogs(int count) {
        List<String> logs = new ArrayList<>();
        Random random = new Random();
        String[] levels = {"INFO", "WARN", "ERROR", "DEBUG"};
        
        for (int i = 0; i < count; i++) {
            String log = String.format(
                "{\"id\":%d,\"level\":\"%s\",\"message\":\"Sample log entry %d\",\"timestamp\":%d}",
                i + 1,
                levels[random.nextInt(levels.length)],
                i + 1,
                System.currentTimeMillis() + i
            );
            logs.add(log);
        }
        
        return logs;
    }
    
    /**
     * Main method - example usage
     */
    public static void main(String[] args) throws Exception {
        String serverHost = "localhost";
        
        if (args.length > 0) {
            serverHost = args[0];
        }
        
        LogClient client = new LogClient(serverHost);
        System.out.println("=== Log Client ===");
        System.out.println("Server: " + serverHost + ":" + DEFAULT_PORT);
        
        // Example 1: Send single logs
        System.out.println("\n--- Sending 100 Single Logs ---");
        String Ty = "fail";
        for (int i = 1; i <= 10; i++) {

            switch(i%3){
                case 0:
                    Ty = "api";
                    break;
                case 1:
                    Ty = "firewall";
                    break;
                case 2:
                    Ty = "auth";
                    break;
            }


            String log = String.format(
                "{\"id\":%d,\"timestamp\":%d,\"Type\":\"%s\",\"message\":\"Single log %d\"}",
                i, System.currentTimeMillis(), Ty, i
            );
            try {
                client.sendSingleLog(log);
                Thread.sleep(100);
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
            }
        }
        
        // Check status
        System.out.println("\n--- Status Check ---");
        try {
            String status = client.getStatus();
            System.out.println(status);
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
        
        // Example 2: Send packet with 10 logs
        /*System.out.println("\n--- Sending Packet (10 Logs) ---");
        List<String> logs = generateSampleLogs(10);
        try {
            client.sendMultipleLogs(logs);
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }*/
        
        // Example 3: Send multiple packets to reach threshold
        /*System.out.println("\n--- Sending Multiple Packets ---");
        for (int packet = 1; packet <= 5; packet++) {
            System.out.println("Packet #" + packet);
            List<String> batchLogs = generateSampleLogs(7);
            try {
                client.sendMultipleLogs(batchLogs);
                Thread.sleep(200);
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
            }
        }
        */
        // Final status
        System.out.println("\n--- Final Status ---");
        try {
            String status = client.getStatus();
            System.out.println(status);
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
        
        // Flush remaining logs
        System.out.println("\n--- Flushing Remaining Logs ---");
        try {
            String flushResponse = client.flushServer();
            System.out.println(flushResponse);
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
        
        System.out.println("\n=== Done ===");
        System.out.println("Check 'concatenated_logs' directory on server");
    }
}