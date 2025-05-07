package org.openpdfsign.pkcs11;

/**
 * Simple logger class to replace Slf4j.
 */
public class Logger {
    
    private String name;
    
    /**
     * Constructor for Logger.
     * 
     * @param name The name of the logger
     */
    private Logger(String name) {
        this.name = name;
    }
    
    /**
     * Gets a logger for the specified class.
     * 
     * @param clazz The class to get a logger for
     * @return The logger
     */
    public static Logger getLogger(Class<?> clazz) {
        return new Logger(clazz.getName());
    }
    
    /**
     * Logs a debug message.
     * 
     * @param message The message to log
     */
    public void debug(String message) {
        System.out.println("[DEBUG] " + name + ": " + message);
    }
    
    /**
     * Logs an info message.
     * 
     * @param message The message to log
     */
    public void info(String message) {
        System.out.println("[INFO] " + name + ": " + message);
    }
    
    /**
     * Logs a warning message.
     * 
     * @param message The message to log
     */
    public void warn(String message) {
        System.out.println("[WARN] " + name + ": " + message);
    }
    
    /**
     * Logs an error message.
     * 
     * @param message The message to log
     */
    public void error(String message) {
        System.err.println("[ERROR] " + name + ": " + message);
    }
    
    /**
     * Logs an error message with an exception.
     * 
     * @param message The message to log
     * @param e The exception to log
     */
    public void error(String message, Exception e) {
        System.err.println("[ERROR] " + name + ": " + message + " - " + e.getMessage());
        e.printStackTrace();
    }
}