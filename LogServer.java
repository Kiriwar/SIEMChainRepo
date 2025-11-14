import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import com.sun.net.httpserver.*;

/**
 * Complete Server-side application to receive log packets, hash each log, 
 * and concatenate them into files when threshold is reached
 * Uses log ID for indexing and new hash file format
 */
public class LogServer {
    
    private static final int SERVER_PORT = 8080;
    private static final int LOG_THRESHOLD = 50;
    private static int TIME_THRESHOLD = 10000;
    private static long timer;
    
    private HttpServer server;
    private List<LogEntry> accumulatedLogs = new ArrayList<>();
    private int fileCounter = 0;
    private long logIdCounter = 0; // Global log ID counter
    private String outputDirectory = "Logs";
    
    /**
     * Inner class to represent a log entry with ID
     */
    static class LogEntry {
        long logId;
        String content;
        String logType;
        String siemLogId;
        long timestamp;
        
        public LogEntry(long logId, String content, String logType, String siemLogId) {
            this.logId = logId;
            this.content = content;
            this.logType = logType;
            this.siemLogId = siemLogId;
            this.timestamp = System.currentTimeMillis();
        }
    }
    
    /**
     * Hash content using SHA-256
     */
    public static String hashContent(String content) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content.getBytes());
        
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
    
    /**
     * Extract log type from log content (extracts "type" field from JSON)
     */
    private String extractLogType(String logContent) {
        try {
            if (logContent.contains("\"Type\"")) {
                int start = logContent.indexOf("\"Type\"") + 8;
                int end = logContent.indexOf("\"", start);
                if (end > start) {
                    return logContent.substring(start, end);
                }
            }
        } catch (Exception e) {
            // If parsing fails, return default
        }
        return "UNKNOWN"; // Default type
    }
    
    /**
     * Extract SIEM log ID from log content (extracts "id" field from JSON)
     */
    private String extractSiemLogId(String logContent) {
        try {
            if (logContent.contains("\"id\"")) {
                int start = logContent.indexOf("\"id\"");
                // Find the value after "id":
                int colonPos = logContent.indexOf(":", start);
                int valueStart = colonPos + 1;
                
                // Skip whitespace
                while (valueStart < logContent.length() && 
                       (logContent.charAt(valueStart) == ' ' || logContent.charAt(valueStart) == '\t')) {
                    valueStart++;
                }
                
                // Check if value is string (starts with ") or number
                if (logContent.charAt(valueStart) == '"') {
                    // String value
                    valueStart++;
                    int valueEnd = logContent.indexOf("\"", valueStart);
                    if (valueEnd > valueStart) {
                        return logContent.substring(valueStart, valueEnd);
                    }
                } else {
                    // Number value
                    int valueEnd = valueStart;
                    while (valueEnd < logContent.length() && 
                           (Character.isDigit(logContent.charAt(valueEnd)) || 
                            logContent.charAt(valueEnd) == '.' || 
                            logContent.charAt(valueEnd) == '-')) {
                        valueEnd++;
                    }
                    if (valueEnd > valueStart) {
                        return logContent.substring(valueStart, valueEnd).trim().replaceAll("[,}\\s].*", "");
                    }
                }
            }
        } catch (Exception e) {
            // If parsing fails, return default
        }
        return "N/A"; // Default if no ID found
    }
    
    /**
     * Parse logs from packet (supports single log or array)
     */
    private List<String> parseLogsFromPacket(String packetContent) {
        List<String> logs = new ArrayList<>();
        String trimmed = packetContent.trim();
        
        if (trimmed.startsWith("[")) {
            // Parse JSON array
            String inner = trimmed.substring(1, trimmed.length() - 1).trim();
            int braceCount = 0;
            StringBuilder currentLog = new StringBuilder();
            
            for (int i = 0; i < inner.length(); i++) {
                char c = inner.charAt(i);
                
                if (c == '{') {
                    braceCount++;
                    currentLog.append(c);
                } else if (c == '}') {
                    braceCount--;
                    currentLog.append(c);
                    
                    if (braceCount == 0 && currentLog.length() > 0) {
                        logs.add(currentLog.toString().trim());
                        currentLog = new StringBuilder();
                    }
                } else if (braceCount > 0) {
                    currentLog.append(c);
                }
            }
        } else {
            // Single log
            logs.add(trimmed);
        }
        
        return logs;
    }
    
    /**
     * Process incoming packet
     */
    private synchronized void processPacket(String packetContent) throws Exception {
        List<String> logs = parseLogsFromPacket(packetContent);
        
        System.out.println("Received packet with " + logs.size() + " log(s)");
        
        // Assign log ID and add to accumulated logs
        for (String log : logs) {
            logIdCounter++;
            String logType = extractLogType(log);
            String siemLogId = extractSiemLogId(log);
            LogEntry entry = new LogEntry(logIdCounter, log, logType, siemLogId);
            accumulatedLogs.add(entry);
            
            System.out.println("  Log ID: " + logIdCounter + " | Type: " + logType + " | SIEM_LogID: " + siemLogId);
        }
        
        // Check if threshold reached
        if (accumulatedLogs.size() >= LOG_THRESHOLD) {
            createConcatenatedFile();
        }
        
        System.out.println("Accumulated logs: " + accumulatedLogs.size() + "/" + LOG_THRESHOLD);
    }
    
    /**
     * Create concatenated file when threshold is reached
     */
    private void createConcatenatedFile() throws IOException, NoSuchAlgorithmException {
        fileCounter++;
        
        // Create output directory
        File dir = new File(outputDirectory);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        
        String filename = outputDirectory + "/logs_batch_" + fileCounter + ".json";
        
        // Concatenate logs
        StringBuilder concatenated = new StringBuilder();
        concatenated.append("[\n");
        
        for (int i = 0; i < accumulatedLogs.size(); i++) {
            concatenated.append("  ").append(accumulatedLogs.get(i).content);
            if (i < accumulatedLogs.size() - 1) {
                concatenated.append(",");
            }
            concatenated.append("\n");
        }
        
        concatenated.append("]");
        
        // Write to file
        Files.write(Paths.get(filename), concatenated.toString().getBytes());
        
        // Hash the concatenated file
        String concatenatedHash = hashContent(concatenated.toString());
        
        // Create hash file with new format
        String hashFilename = outputDirectory + "/logs_batch_" + fileCounter + "_LogMetadata.txt";
        StringBuilder hashContent = new StringBuilder();
        
        // Header
        hashContent.append("[\n");
        
        // Log entries with ID, Type, Epoch, and SIEM_LogID
        for (int i = 0; i < accumulatedLogs.size(); i++) {
            LogEntry entry = accumulatedLogs.get(i);
            hashContent.append("  {ID: ").append(entry.logId)
                      .append(", Type: ").append(entry.logType)
                      .append(", Epoch: ").append(fileCounter)
                      .append(", SIEM_LogID: ").append(entry.siemLogId)
                      .append("}");
            
            if (i < accumulatedLogs.size() - 1) {
                hashContent.append(",");
            }
            hashContent.append("\n");
        }
        
        hashContent.append("]\n");
        hashContent.append("HashBatch: ").append(concatenatedHash).append("\n");
        
        Files.write(Paths.get(hashFilename), hashContent.toString().getBytes());
        
        System.out.println("\n*** THRESHOLD REACHED ***");
        System.out.println("Created file: " + filename);
        System.out.println("Created hash file: " + hashFilename);
        System.out.println("Logs in batch: " + accumulatedLogs.size());
        System.out.println("Batch number (Epoch): " + fileCounter);
        System.out.println("Log ID range: " + accumulatedLogs.get(0).logId + 
                          " - " + accumulatedLogs.get(accumulatedLogs.size()-1).logId);
        System.out.println("HashBatch: " + concatenatedHash);
        System.out.println("*************************\n");
        
        // Clear accumulated logs
        callJavaScript(fileCounter);
        accumulatedLogs.clear();
    }
    
    /**
     * Force create file with current logs
     */
    private synchronized void forceCreateFile() throws IOException, NoSuchAlgorithmException {
        if (accumulatedLogs.isEmpty()) {
            System.out.println("No logs to create file");
            return;
        }
        
        System.out.println("Force creating file with " + accumulatedLogs.size() + " logs");
        createConcatenatedFile();
    }
    
    /**
     * Start the HTTP server
     */
    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(SERVER_PORT), 0);
        
        // Upload endpoint
        server.createContext("/upload", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if ("POST".equals(exchange.getRequestMethod())) {
                    try {
                        InputStream is = exchange.getRequestBody();
                        String packetContent = new String(is.readAllBytes());
                        
                        processPacket(packetContent);
                        
                        String response = "Packet received. Accumulated: " + 
                                        accumulatedLogs.size() + "/" + LOG_THRESHOLD +
                                        " | Current Log ID: " + logIdCounter;
                        exchange.sendResponseHeaders(200, response.length());
                        OutputStream os = exchange.getResponseBody();
                        os.write(response.getBytes());
                        os.close();
                        
                    } catch (Exception e) {
                        e.printStackTrace();
                        String response = "Error: " + e.getMessage();
                        exchange.sendResponseHeaders(500, response.length());
                        OutputStream os = exchange.getResponseBody();
                        os.write(response.getBytes());
                        os.close();
                    }
                } else {
                    String response = "Use POST method";
                    exchange.sendResponseHeaders(405, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            }
        });
        
        // Status endpoint
        server.createContext("/status", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if ("GET".equals(exchange.getRequestMethod())) {
                    String response = String.format(
                        "{\n  \"accumulated_logs\": %d,\n  \"threshold\": %d,\n  \"files_created\": %d,\n  \"current_log_id\": %d,\n  \"progress_percent\": %d\n}",
                        accumulatedLogs.size(),
                        LOG_THRESHOLD,
                        fileCounter,
                        logIdCounter,
                        (accumulatedLogs.size() * 100) / LOG_THRESHOLD
                    );
                    
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            }
        });
        
        // Flush endpoint
        server.createContext("/flush", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if ("POST".equals(exchange.getRequestMethod())) {
                    try {
                        forceCreateFile();
                        String response = "File created successfully";
                        exchange.sendResponseHeaders(200, response.length());
                        OutputStream os = exchange.getResponseBody();
                        os.write(response.getBytes());
                        os.close();
                    } catch (Exception e) {
                        String response = "Error: " + e.getMessage();
                        exchange.sendResponseHeaders(500, response.length());
                        OutputStream os = exchange.getResponseBody();
                        os.write(response.getBytes());
                        os.close();
                    }
                }
            }
        });
        
        server.setExecutor(null);
        server.start();
        
        System.out.println("=== Log Processing Server Started ===");
        System.out.println("Server running on port " + SERVER_PORT);
        System.out.println("Log threshold: " + LOG_THRESHOLD);
        System.out.println("Output directory: " + outputDirectory);
        System.out.println("\nEndpoints:");
        System.out.println("  POST http://localhost:" + SERVER_PORT + "/upload");
        System.out.println("  GET  http://localhost:" + SERVER_PORT + "/status");
        System.out.println("  POST http://localhost:" + SERVER_PORT + "/flush");
        System.out.println("\nPress Enter to stop...\n");
    }
    
    /**
     * Stop the server
     */
    public void stop() {
        if (server != null) {
            if (!accumulatedLogs.isEmpty()) {
                try {
                    System.out.println("Creating file with remaining logs...");
                    forceCreateFile();
                } catch (IOException | NoSuchAlgorithmException e) {
                    System.err.println("Error: " + e.getMessage());
                }
            }
            server.stop(0);
            System.out.println("Server stopped");
        }
    }

/**
 * Call JavaScript file with epoch value
 */
    private void callJavaScript(int epoch) throws IOException, NoSuchAlgorithmException {
    ProcessBuilder pb = new ProcessBuilder("node", "merkleOps/test-import.js", String.valueOf(epoch));
    pb.redirectErrorStream(true);
    
    Process process = pb.start();
    
    // Read output from JavaScript
    /*BufferedReader reader = new BufferedReader(
        new InputStreamReader(process.getInputStream()));
    
    StringBuilder output = new StringBuilder();
    String line;
    while ((line = reader.readLine()) != null) {
        output.append(line);
    }
    
    int exitCode = process.waitFor();
    
    if (exitCode != 0) {
        throw new Exception("JavaScript execution failed with exit code: " + exitCode);
    }*/
}
    
    /**
     * Main method
     */
    public static void main(String[] args) throws Exception {
        LogServer server = new LogServer();
        server.start();
        //System.in.read();
        //server.stop();
        timer = System.currentTimeMillis();
        while (true)
        {
        try {Thread.sleep(7000);}
        catch (InterruptedException e) {System.out.println(e);}
        //System.out.println(timer);

        if ((System.currentTimeMillis()-timer) >= TIME_THRESHOLD){
            server.forceCreateFile();
            timer = System.currentTimeMillis();
        }
        }
    }
}