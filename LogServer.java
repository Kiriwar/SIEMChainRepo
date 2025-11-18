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
    * Extract field value from simple JSON string
    */
    private String extractJsonField(String json, String fieldName) {
        try {
            String searchKey = "\"" + fieldName + "\"";
            int start = json.indexOf(searchKey);
            if (start == -1) return null;
            
            int colonPos = json.indexOf(":", start);
            int valueStart = colonPos + 1;
            
            // Skip whitespace
            while (valueStart < json.length() && 
                (json.charAt(valueStart) == ' ' || json.charAt(valueStart) == '\t')) {
                valueStart++;
            }
            
            // Check if string or number
            if (json.charAt(valueStart) == '"') {
                valueStart++;
                int valueEnd = json.indexOf("\"", valueStart);
                return json.substring(valueStart, valueEnd);
            } else {
                int valueEnd = valueStart;
                while (valueEnd < json.length() && 
                    (Character.isDigit(json.charAt(valueEnd)) || 
                        json.charAt(valueEnd) == '.' || 
                        json.charAt(valueEnd) == '-')) {
                    valueEnd++;
                }
                return json.substring(valueStart, valueEnd).trim().replaceAll("[,}\\s].*", "");
            }
        } catch (Exception e) {
            return null;
        }
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

    // Add this new context AFTER the /flush endpoint
    server.createContext("/verify", new HttpHandler() {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if ("POST".equals(exchange.getRequestMethod())) {
            try {
                InputStream is = exchange.getRequestBody();
                String requestBody = new String(is.readAllBytes());
                
                System.out.println("Received verification request: " + requestBody);
                
                // NEW: Parse rawLog from request
                // Expected format: {"rawLog": {"id":25,"timestamp":...,"Type":"firewall",...}}
                String rawLogJson = extractRawLog(requestBody);
                
                if (rawLogJson == null) {
                    throw new Exception("Request must contain 'rawLog' field");
                }
                
                // Step 1: Call coarse-grained verification with raw log
                String coarseResult = callNodeScriptWithRawLog("coarse", rawLogJson);
                JSONResult coarse = parseJSON(coarseResult);
                
                System.out.println("Coarse result: " + coarseResult);
                
                String response;
                
                if (coarse.valid) {
                    // Coarse-grained passed - log is valid
                    response = String.format(
                        "{\"valid\":true,\"method\":\"coarse\",\"message\":\"Raw log verified (concat hash match)\"}"
                    );
                } else {
                    // Coarse-grained failed - send Alert 1
                    if (coarse.alert != null) {
                        sendAlert(coarse.alert);
                        System.out.println("\nALERT 1 SENT: Raw log hash mismatch - concat hash mismatch");
                    }
                    
                    // Extract metadata for fine-grained check
                    String logId = extractJsonField(coarseResult, "logId");
                    String logType = extractJsonField(coarseResult, "logType");
                    String epochIdStr = extractJsonField(coarseResult, "epochId");
                    if (logId != null && logType != null && epochIdStr != null) {
                        int epochId = Integer.parseInt(epochIdStr);
                        // Step 2: Call fine-grained verification
                        String fineResult = callNodeScript("fine", logId, logType, epochId, rawLogJson);
                        JSONResult fine = parseJSON(fineResult);
                        
                        System.out.println("Fine result: " + fineResult);
                        
                        if (fine.valid) {
                            // Merkle proof valid but concat failed (shouldn't happen normally)
                            response = String.format(
                                "{\"valid\":true,\"method\":\"fine\",\"message\":\"Verified by Merkle proof (anomaly detected in concat)\"}"
                            );
                        } else {
                            System.out.println(fine.alert);
                            // Actually tampered - send Alert 2
                            if (fine.alert != null) {
                                System.out.println("after cond");
                                sendAlert(fine.alert);
                                System.out.println("\n🚨 ALERT 2 SENT: Specific log tampered (Merkle proof failed)");
                            }
                            response = String.format(
                                "{\"valid\":false,\"method\":\"fine\",\"message\":\"CRITICAL: Log has been tampered\",\"logId\":\"%s\"}",
                                logId
                            );
                        }
                    } else {
                        response = String.format(
                            "{\"valid\":false,\"error\":\"Could not extract metadata from coarse verification result\"}"
                        );
                    }
                }
                
                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
                
            } catch (Exception e) {
                e.printStackTrace();
                String response = "{\"error\":\"" + e.getMessage() + "\"}";
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

    private String extractRawLog(String requestBody) {
    try {
        int start = requestBody.indexOf("\"rawLog\"");
        if (start == -1) return null;
        
        int objectStart = requestBody.indexOf("{", start);
        if (objectStart == -1) return null;
        
        int braceCount = 0;
        int objectEnd = objectStart;
        
        for (int i = objectStart; i < requestBody.length(); i++) {
            if (requestBody.charAt(i) == '{') braceCount++;
            if (requestBody.charAt(i) == '}') {
                braceCount--;
                if (braceCount == 0) {
                    objectEnd = i;
                    break;
                }
            }
        }
        
        return requestBody.substring(objectStart, objectEnd + 1);
    } catch (Exception e) {
        return null;
    }
    }

    private String callNodeScriptWithRawLog(String mode, String rawLogJson) 
        throws IOException, InterruptedException {
    
    ProcessBuilder pb = new ProcessBuilder("node", "merkleOps/verify-log.js", mode);
    pb.redirectErrorStream(true);
    
    Process process = pb.start();
    
    // Write rawLog to stdin
    PrintWriter writer = new PrintWriter(process.getOutputStream());
    writer.println(rawLogJson);
    writer.flush();
    writer.close();
    
    // Read output
    BufferedReader reader = new BufferedReader(
        new InputStreamReader(process.getInputStream())
    );
    
    StringBuilder output = new StringBuilder();
    String line;
    while ((line = reader.readLine()) != null) {
        output.append(line);
    }
    
    process.waitFor();
    return output.toString();
}

    class JSONResult {
    boolean valid;
    String alert;
    }

    private JSONResult parseJSON(String json) {
    JSONResult result = new JSONResult();
    result.valid = json.contains("\"valid\":true") || json.contains("\"valid\": true");
    
    // Extract alert if exists
    if (json.contains("\"alert\":{")) {
        int start = json.indexOf("\"alert\":{");
        int end = findMatchingBrace(json, start + 8);
        result.alert = json.substring(start + 8, end + 1);
    }
    
    return result;
    }

    private int findMatchingBrace(String json, int start) {
        int count = 1;
        for (int i = start + 1; i < json.length(); i++) {
            if (json.charAt(i) == '{') count++;
            if (json.charAt(i) == '}') count--;
            if (count == 0) return i;
        }
        return json.length() - 1;
    }

    private String callNodeScript(String mode, String logId, String logType, int epochId, String rawLogJson) 
        throws IOException, InterruptedException {
    ProcessBuilder pb = new ProcessBuilder(
        "node", "merkleOps/verify-log.js", mode, logId, logType, String.valueOf(epochId)
    );
    pb.redirectErrorStream(true);

    Process process = pb.start();
    
    PrintWriter writer = new PrintWriter(process.getOutputStream());
    writer.println(rawLogJson);
    writer.flush();
    writer.close();
    BufferedReader reader = new BufferedReader(
        new InputStreamReader(process.getInputStream())
    );
    
    StringBuilder output = new StringBuilder();
    String line;
    while ((line = reader.readLine()) != null) {
        output.append(line);
    }
    
    process.waitFor();
    return output.toString();
    }

    private void sendAlert(String alertJson) {
    System.out.println("\n========== ALERT ==========");
    System.out.println(alertJson);
    System.out.println("===========================\n");

    sendAlertToSIEM(alertJson);
    }

    private void sendAlertToSIEM(String alertJson) {
    final String SIEM_HOST = "localhost";
    final int SIEM_PORT = 9999;
    
    try {
        Socket socket = new Socket(SIEM_HOST, SIEM_PORT);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        
        // Send as HTTP POST
        out.println("POST / HTTP/1.1");
        out.println("Host: " + SIEM_HOST);
        out.println("Content-Type: application/json");
        out.println("Content-Length: " + alertJson.length());
        out.println();
        out.println(alertJson);
        out.flush();
        
        socket.close();
        
        System.out.println("Alert sent to SIEM (" + SIEM_HOST + ":" + SIEM_PORT + ")");
        
    } catch (Exception e) {
        System.err.println("Failed to send alert to SIEM: " + e.getMessage());
    }
}
    
    /**
     * Call JavaScript file with epoch value
     */
    private void callJavaScript(int epoch) throws IOException, NoSuchAlgorithmException {
        System.out.println("\n=== CALLING JAVASCRIPT ===");
        System.out.println("Epoch: " + epoch);
        System.out.println("Command: node merkleOps/test-import.js " + epoch);
        
        ProcessBuilder pb = new ProcessBuilder("node", "merkleOps/test-import.js", String.valueOf(epoch));
        pb.redirectErrorStream(true);
        
        Process process = pb.start();
        
        // UNCOMMENT THIS - We need to see JavaScript output!
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        String line;
        System.out.println("JavaScript Output:");
        while ((line = reader.readLine()) != null) {
            System.out.println("  JS: " + line);
        }
        
        /*int exitCode = process.waitFor();
        System.out.println("JavaScript exit code: " + exitCode);
        
        if (exitCode != 0) {
            System.err.println("ERROR: JavaScript failed!");
        }*/
        System.out.println("=== JAVASCRIPT DONE ===\n");
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