package org.wso2.carbon.identity.custom.federated.authenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;


import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class HttpPostRequest {
    private final String apiUrl;


    public HttpPostRequest(String apiUrl, AuthenticationContext context) {
        this.apiUrl = apiUrl;
    }

    // Method to send POST request and return success status
    public boolean sendPostRequest(String username, String password,AuthenticationContext context) throws IOException {
        HttpURLConnection connection = null;
        boolean isSuccess = false;

        try {
            // Create URL object
            URL url = new URL(apiUrl);
            // Create connection
            connection = (HttpURLConnection) url.openConnection();


            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

            String contentType = authenticatorProperties.get(CustomFederatedAuthenticatorConstants.ACCEPT_HEADER);
            String acceptHeader = authenticatorProperties.get(CustomFederatedAuthenticatorConstants.ACCEPT_HEADER);
            String jsonTemplate = authenticatorProperties.get(CustomFederatedAuthenticatorConstants.JSON_TEMPLATE);


            // Set request method to POST
            connection.setRequestMethod("POST");
            // Set headers
            connection.setRequestProperty("Content-Type", contentType);
            connection.setRequestProperty("Accept", acceptHeader);
            connection.setDoOutput(true);

            // Create JSON body
//            String jsonInputString = String.format("{\"username\": \"%s\", \"password\": \"%s\"}", username, password);

            String jsonInputString = jsonTemplate
                    .replace("{$username}", username)
                    .replace("{$password}", password);


            // Write JSON body to output stream
            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = jsonInputString.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // Close the output stream
            connection.getOutputStream().close();

            // Check the response code and set isSuccess
            int responseCode = connection.getResponseCode();
            isSuccess = (responseCode == HttpURLConnection.HTTP_OK);

            // Log response code
            System.out.println("POST Response Code :: " + responseCode);

        } catch (IOException e) {
            e.printStackTrace();
            throw e;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }

        return isSuccess;
    }
}
