<?php

namespace MailUp;

/**
 * @author  Filippo "Pirosauro" Bovo
 * @package MailUp API client
 * @version 0.1.0
 * @license Apache 2.0
 */

class Client {

    const CONTENT_TYPE_JSON  =  'JSON';
    const CONTENT_TYPE_XML   =  'XML';

    private $logon_endpoint              =  "https://services.mailup.com/Authorization/OAuth/LogOn";
    private $authorization_endpoint      =  "https://services.mailup.com/Authorization/OAuth/Authorization";
    private $token_endpoint              =  "https://services.mailup.com/Authorization/OAuth/Token";
    private $console_endpoint            =  "https://services.mailup.com/API/v1.1/Rest/ConsoleService.svc";
    private $mail_statistics_endpoint    =  "https://services.mailup.com/API/v1.1/Rest/MailStatisticsService.svc";
    private $sms_endpoint                =  "https://sendsms.mailup.com/api/v2.0";

    private $client_id;
    private $client_secret;
    private $callback_uri;
    private $access_token;
    private $refresh_token;
    private $basic_auth;
    private $username;

    protected $logger;

    protected $request;
    protected $response;

    /**
     * Constructor
     *
     * @param   string  $client_id
     * @param   string  $client_secret
     * @param   string  $callback_uri
     */
    public function __construct($client_id, $client_secret, $callback_uri) {
        $this->client_id         =  $client_id;
        $this->client_secret     =  $client_secret;
        $this->callback_uri      =  $callback_uri;

        $this->logger            =  new Logger();

        $this->loadToken();
    }

    /**
     * Set a new logger instance
     *
     * @param   Logger  $logger
     * @return  self
     */
    public function setLogger(Logger $logger) {
        $this->logger    =  $logger;

        return $this;
    }

    /**
     * Get the logger instance
     *
     * @return  Logger
     */
    public function getLogger() {
        return $this->logger;
    }

    /**
     * Get the logon endpoint
     *
     * @return  string
     */
    public function getLogonEndpoint() {
        return $this->logon_endpoint;
    }

    /**
     * Set the logon endpoint
     *
     * @param   string  $endpoint   a valid endpoint URL
     * @return  self
     */
    public function setLogonEndpoint($endpoint) {
        if (filter_var($endpoint, FILTER_VALIDATE_URL) !== FALSE) {
            $this->logon_endpoint   =  $endpoint;

            $this->logger->setMessage('DEBUG', 'LogOn endpoint set to ' . $endpoint);
        }
        else {
            throw new Exception(sprintf('Argument 1 passed to %s must be a valid URL.', __METHOD__));
        }

        return $this;
    }

    /**
     * Get the authorization endpoint
     *
     * @return  string
     */
    public function getAuthorizationEndpoint() {
        return $this->authorization_endpoint;
    }

    /**
     * Set the authorization endpoint
     *
     * @param   string  $endpoint   a valid endpoint URL
     * @return  self
     */
    public function setAuthorizationEndpoint($endpoint) {
        if (filter_var($endpoint, FILTER_VALIDATE_URL) !== FALSE) {
            $this->authorization_endpoint   =  $endpoint;

            $this->logger->setMessage('DEBUG', 'Authorization endpoint set to ' . $endpoint);
        }
        else {
            throw new Exception(sprintf('Argument 1 passed to %s must be a valid URL.', __METHOD__));
        }

        return $this;
    }

    /**
     * Get the token endpoint
     *
     * @return  string
     */
    public function getTokenEndpoint() {
        return $this->token_endpoint;
    }

    /**
     * Set the token endpoint
     *
     * @param   string  $endpoint   a valid endpoint URL
     * @return  self
     */
    public function setTokenEndpoint($endpoint) {
        if (filter_var($endpoint, FILTER_VALIDATE_URL) !== FALSE) {
            $this->token_endpoint   =  $endpoint;

            $this->logger->setMessage('DEBUG', 'Token endpoint set to ' . $endpoint);
        }
        else {
            throw new Exception(sprintf('Argument 1 passed to %s must be a valid URL.', __METHOD__));
        }

        return $this;
    }

    /**
     * Get the console endpoint
     *
     * @return  string
     */
    public function getConsoleEndpoint() {
        return $this->console_endpoint;
    }

    /**
     * Set the console endpoint
     *
     * @param   string  $endpoint   a valid endpoint URL
     * @return  self
     */
    public function setConsoleEndpoint($endpoint) {
        if (filter_var($endpoint, FILTER_VALIDATE_URL) !== FALSE) {
            $this->console_endpoint  =  $endpoint;

            $this->logger->setMessage('DEBUG', 'Console endpoint set to ' . $endpoint);
        }
        else {
            throw new Exception(sprintf('Argument 1 passed to %s must be a valid URL.', __METHOD__));
        }

        return $this;
    }

    /**
     * Get the mail statistics endpoint
     *
     * @return  string
     */
    public function getMailStatisticsEndpoint() {
        return $this->mail_statistics_endpoint;
    }

    /**
     * Set the mail statistics endpoint
     *
     * @param   string  $endpoint   a valid endpoint URL
     * @return  self
     */
    public function setMailStatisticsEndpoint($endpoint) {
        if (filter_var($endpoint, FILTER_VALIDATE_URL) !== FALSE) {
            $this->mail_statistics_endpoint  =  $endpoint;

            $this->logger->setMessage('DEBUG', 'Mail Statistics endpoint set to ' . $endpoint);
        }
        else {
            throw new Exception(sprintf('Argument 1 passed to %s must be a valid URL.', __METHOD__));
        }

        return $this;
    }

    /**
     * Get the SMS endpoint
     *
     * @return  string
     */
    public function getSMSEndpoint() {
        return $this->sms_endpoint;
    }

    /**
     * Set the SMS endpoint
     *
     * @param   string  $endpoint   a valid endpoint URL
     * @return  self
     */
    public function setSMSEndpoint($endpoint) {
        if (filter_var($endpoint, FILTER_VALIDATE_URL) !== FALSE) {
            $this->sms_endpoint  =  $endpoint;

            $this->logger->setMessage('DEBUG', 'SMS endpoint set to ' . $endpoint);
        }
        else {
            throw new Exception(sprintf('Argument 1 passed to %s must be a valid URL.', __METHOD__));
        }

        return $this;
    }

    /**
     * Get the client ID
     *
     * @return  string
     */
    public function getClientID() {
        return $this->client_id;
    }

    /**
     * Set the client ID
     *
     * @param   string  $client_id
     * @return  self
     */
    public function setClientID($client_id) {
        $this->client_id     =  $client_id;

        $this->logger->setMessage('DEBUG', 'Client ID set to ' . $client_id);

        return $this;
    }

    /**
     * Get the client secret
     *
     * @return  string
     */
    public function getClientSecret() {
        return $this->client_secret;
    }

    /**
     * Set the client secret
     *
     * @param   string  $client_secret
     * @return  self
     */
    public function setClientSecret($client_secret) {
        $this->client_secret     =  $client_secret;

        $this->logger->setMessage('DEBUG', 'Client Secret set to ' . $client_secret);

        return $this;
    }

    /**
     * Get the callback URI
     *
     * @return  string
     */
    public function getCallbackURI() {
        return $this->callback_uri;
    }

    /**
     * Set the callback URL
     *
     * @param   string  $callback_uri   a valid URL
     * @return  self
     */
    public function setCallbackURI($callback_uri) {
        if (filter_var($callback_uri, FILTER_VALIDATE_URL) !== FALSE) {
            $this->callback_uri  =  $callback_uri;

            $this->logger->setMessage('DEBUG', 'Callback URL set to ' . $callback_uri);
        }
        else {
            throw new Exception(sprintf('Argument 1 passed to %s must be a valid URL.', __METHOD__));
        }

        return $this;
    }

    /**
     * Get the access token
     *
     * @return  string
     */
    public function getAccessToken() {
        return $this->access_token;
    }

    /**
     * Set the access token
     *
     * @param   string  $token
     * @return  self
     */
    public function setAccessToken($token) {
        $this->access_token  =  $token;

        $this->logger->setMessage('DEBUG', 'Access Token set to ' . $token);

        return $this;
    }

    /**
     * Get the refresh token
     *
     * @return  string
     */
    public function getRefreshToken() {
        return $this->refresh_token;
    }

    /**
     * Set the refresh token
     *
     * @param   string  $token
     * @return  self
     */
    public function setRefreshToken($token) {
        $this->refresh_token     =  $token;

        $this->logger->setMessage('DEBUG', 'Refresh Token set to ' . $token);

        return $this;
    }

    /**
     * Get base64 encoded basic auth string
     *
     * @return  string
     */
    public function getBasicAuth() {
        return $this->basic_auth;
    }

    /**
     * Get the user name
     *
     * @param   bool    $strip  returns just the numeric part
     * @return  string
     */
    public function getUsername( $strip = FALSE ) {
        if ( $strip ) {
            return preg_replace( '#[\D]+#', '', $this->username );
        }
        else {
            return $this->username;
        }
    }

    /**
     * Get the logon URI
     *
     * @return  string
     */
    public function getLogonURI() {
        $query   =  [
            'client_id'      => $this->getClientID(),
            'client_secret'  => $this->getClientSecret(),
            'response_type'  => 'code',
            'redirect_uri'   => $this->getCallbackURI(),
        ];
        $url     =  $this->getLogonEndpoint() . '?' . http_build_query($query);

        return $url;
    }

    /**
     * Returns the latest request if any
     *
     * @return  mixed
     */
    public function getRequest() {
        return $this->request;
    }

    /**
     * Returns the latest response if any
     *
     * @return  mixed
     */
    public function getResponse() {
        return $this->response;
    }

    /**
     * Executes the login and returns the access token
     *
     * @param   string  $login      username used to login into MailUp's console
     * @param   string  $password   password used to login into MailUp's console
     * @return  self
     */
    public function doLogon($username, $password) {
        $this->basic_auth    =  base64_encode( $username . ':' . $password );
        $this->username      =  $username;

        $this->logger->setMessage('DEBUG', 'Attempt to LogOn with user ' . $username);

        return $this->retreiveAccessToken($username, $password);
    }

    /**
     * Retrieves the access token from code
     *
     * @param   string  $code
     * @return  self
     */
    public function retreiveAccessTokenWithCode($code) {
        $this->logger->setMessage('DEBUG', 'Attempt to retrieve Access Token with code ' . $code);

        $url     =  $this->getTokenEndpoint() . '?' . http_build_query([
            'code'           => $code,
            'grant_type'     => 'authorization_code',
        ]);

        $this->request   =  (new Request())
            ->setOption(CURLOPT_URL, $url)
            ->setOption(CURLOPT_RETURNTRANSFER, TRUE)
            ->setOption(CURLOPT_SSL_VERIFYPEER, FALSE)
            ->setOption(CURLOPT_SSL_VERIFYHOST, FALSE);

        $this->logger->setRequest($this->request, 'GET');

        $this->response  =  $this->request->execute();
        $code            =  $this->response->getStatusCode();

        $this->logger->setResponse($this->response);

        if (($code != 200) && ($code != 302)) {
            throw new Exception(sprintf("Authorization failed with response code %d", $code));
        }

        $result  =  json_decode($this->response->getBody());

        if (json_last_error() == JSON_ERROR_NONE) {
            $this->setAccessToken($result->access_token);
            $this->setRefreshToken($result->refresh_token);
        }
        else {
            if (function_exists('json_last_error_msg')) {
                throw new Exception(sprintf("Failed to parse JSON string: %s", json_last_error_msg()));
            }
            else {
                throw new Exception(sprintf("Failed to parse JSON string (%d)", json_last_error()));
            }
        }

        $this->saveToken();

        return $this;
    }

    /**
     * Tries to get the access token
     *
     * @param   string  $login      username used to login into MailUp's console
     * @param   string  $password   password used to login into MailUp's console
     * @return  self
     */
    protected function retreiveAccessToken($username, $password) {
        $this->logger->setMessage('DEBUG', 'Attempt to retrieve Access Token with user ' . $username);

        $body    =  http_build_query([
            'grant_type'     => 'password',
            'username'       => $username,
            'password'       => $password,
            'client_id'      => $this->getClientID(),
            'client_secret'  => $this->getClientSecret(),
        ]);

        $headers     =  [
            'Content-length'     => strlen($body),
            'Accept'             => 'application/json',
            'Authorization'      => 'Basic ' . base64_encode($this->getClientID() . ':' . $this->getClientSecret()),
        ];

        $this->request   =  (new Request())
            ->setOption(CURLOPT_URL, $this->getTokenEndpoint())
            ->setOption(CURLOPT_RETURNTRANSFER, TRUE)
            ->setOption(CURLOPT_SSL_VERIFYPEER, FALSE)
            ->setOption(CURLOPT_SSL_VERIFYHOST, FALSE)
            ->setOption(CURLOPT_POST, TRUE)
            ->setOption(CURLOPT_HTTPHEADER, $headers)
            ->setOption(CURLOPT_POSTFIELDS, $body);

        $this->logger->setRequest($this->request, 'POST');

        $this->response  =  $this->request->execute();
        $code            =  $this->response->getStatusCode();

        $this->logger->setResponse($this->response);

        if (($code != 200) && ($code != 302)) {
            throw new Exception(sprintf("Authorization failed with response code %d", $code));
        }

        // {"access_token":"2e0n3J1r2o3U2o2B0g111V361e2e23173i0I0R04081J1P1R0M2D0c1M0O3G1t3g1d2P031e0M2V2S2R253x293d422L1j3R2C0m3u2v1J2j0D1k1w0T0n1D3b3i0o2Q","expires_in":900,"refresh_token":"0Q2I291A0h2t382C0j013n2V2B0X1o0R1D1i3F09083I3g210X3G302e3b361l1J2I2x3Y0R3n240e0E030v1S3h3P1F1y3038443842342J2g0p1a3l0X0q0r0c160y"}
        $result  =  json_decode($this->response->getBody());

        if (json_last_error() == JSON_ERROR_NONE) {
            $this->setAccessToken($result->access_token);
            $this->setRefreshToken($result->refresh_token);
        }
        else {
            if (function_exists('json_last_error_msg')) {
                throw new Exception(sprintf("Failed to parse JSON string: %s", json_last_error_msg()));
            }
            else {
                throw new Exception(sprintf("Failed to parse JSON string (%d)", json_last_error()));
            }
        }

        $this->saveToken();

        return $this;
    }

    /**
     * Refreshes the token
     *
     * @return  self
     */
    public function refreshAccessToken() {
        $this->logger->setMessage('DEBUG', 'Attempt to refresh the token');

        $body    =  http_build_query([
            'client_id'      => $this->getClientID(),
            'client_secret'  => $this->getClientSecret(),
            'refresh_token'  => $this->getRefreshToken(),
            'grant_type'     => 'refresh_token',
        ]);

        $headers     =  [
            'Content-length: ' . strlen($body),
            'Accept: application/x-www-form-urlencoded',
        ];

        $this->request   =  (new Request())
            ->setOption(CURLOPT_URL, $this->getTokenEndpoint())
            ->setOption(CURLOPT_RETURNTRANSFER, TRUE)
            ->setOption(CURLOPT_SSL_VERIFYPEER, FALSE)
            ->setOption(CURLOPT_SSL_VERIFYHOST, FALSE)
            ->setOption(CURLOPT_POST, TRUE)
            ->setOption(CURLOPT_POSTFIELDS, $body)
            ->setOption(CURLOPT_HTTPHEADER, $headers);

        $this->logger->setRequest($this->request, 'POST');

        $this->response  =  $this->request->execute();
        $code            =  $this->response->getStatusCode();

        $this->logger->setResponse($this->response);

        if (($code != 200) && ($code != 302)) {
            throw new Exception(sprintf("Authorization failed with response code %d", $code));
        }

        $result  =  json_decode($this->response->getBody());

        if (json_last_error() == JSON_ERROR_NONE) {
            $this->setAccessToken($result->access_token);
            $this->setRefreshToken($result->refresh_token);
        }
        else {
            if (function_exists('json_last_error_msg')) {
                throw new Exception(sprintf("Failed to parse JSON string: %s", json_last_error_msg()));
            }
            else {
                throw new Exception(sprintf("Failed to parse JSON string (%d)", json_last_error()));
            }
        }

        $this->saveToken();

        return $this;
    }

    /**
     * Call REST method
     *
     * @param   string  $url            endpoint URL
     * @param   string  $verb
     * @param   string  $body
     * @param   string  $content_type
     * @param   bool    $refresh
     * @return  mixed
     */
    public function callMethod($url, $verb, $body = '', $content_type = self::CONTENT_TYPE_JSON, $refresh = TRUE) {
        $temp    =  NULL;
        $sms     =  (stripos($url, $this->sms_endpoint) === 0) ? TRUE : FALSE;

        $this->request   =  (new Request())
            ->setOption(CURLOPT_URL, $url)
            ->setOption(CURLOPT_RETURNTRANSFER, TRUE)
            ->setOption(CURLOPT_SSL_VERIFYPEER, FALSE)
            ->setOption(CURLOPT_SSL_VERIFYHOST, FALSE);

        if ($verb == "POST") {
            if ( $sms ) {
                $headers     =  [
                    'Content-type: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Content-length: ' . strlen($body),
                    'Accept: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Authorization: Basic ' . $this->getBasicAuth(),
                ];
            }
            else {
                $headers     =  [
                    'Content-type: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Content-length: ' . strlen($body),
                    'Accept: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Authorization: Bearer ' . $this->getAccessToken(),
                ];
            }

            $this->request
                ->setOption(CURLOPT_POST, TRUE)
                ->setOption(CURLOPT_POSTFIELDS, $body)
                ->setOption(CURLOPT_HTTPHEADER, $headers);
        }
        else if ($verb == "PUT") {
            $temp        =  tmpfile();

            if ( $sms ) {
                $headers     =  [
                    'Content-type: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Content-length: ' . strlen($body),
                    'Accept: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Authorization: Basic ' . $this->getBasicAuth(),
                ];
            }
            else {
                $headers     =  [
                    'Content-type: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Content-length: ' . strlen($body),
                    'Accept: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Authorization: Bearer ' . $this->getAccessToken(),
                ];
            }

            fwrite($temp, $body);
            fseek($temp, 0);

            $this->request
                ->setOption(CURLOPT_PUT, TRUE)
                ->setOption(CURLOPT_HTTPHEADER, $headers)
                ->setOption(CURLOPT_INFILE, $temp)
                ->setOption(CURLOPT_INFILESIZE, strlen($body));
        }
        else if ($verb == "DELETE") {
            $body        =  '';

            if ( $sms ) {
                $headers     =  [
                    'Content-type: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Content-length: ' . strlen($body),
                    'Accept: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Authorization: Basic ' . $this->getBasicAuth(),
                ];
            }
            else {
                $headers     =  [
                    'Content-type: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Content-length: ' . strlen($body),
                    'Accept: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Authorization: Bearer ' . $this->getAccessToken(),
                ];
            }

            $this->request
                ->setOption(CURLOPT_CUSTOMREQUEST, "DELETE")
                ->setOption(CURLOPT_HTTPHEADER, $headers);
        }
        else {
            $body        =  '';

            if ( $sms ) {
                $headers     =  [
                    'Content-type: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Content-length: ' . strlen($body),
                    'Accept: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Authorization: Basic ' . $this->getBasicAuth(),
                ];
            }
            else {
                $headers     =  [
                    'Content-type: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Content-length: ' . strlen($body),
                    'Accept: ' . (($content_type == "XML") ? "application/xml" : "application/json"),
                    'Authorization: Bearer ' . $this->getAccessToken(),
                ];
            }

            $this->request
                ->setOption(CURLOPT_HTTPHEADER, $headers);
        }

        $this->logger->setRequest($this->request, $verb);

        $this->response  =  $this->request->execute();
        $code            =  $this->response->getStatusCode();

        $this->logger->setResponse($this->response);

        if ($temp)  {
            fclose($temp);
        }

        if (($code == 401) && $refresh) {
            $this->refreshAccessToken();

            return $this->callMethod($url, $verb, $body, $content_type, FALSE);
        }
        else if (($code == 401) && !$refresh) {
            throw new Exception(sprintf("Authorization failed with response code %d", $code));

            return FALSE;
        }
        else if (($code != 200) && ($code != 302)) {
            throw new Exception(sprintf("Authorization failed with response code %d", $code));

            return FALSE;
        }

        return $this->response;
    }

    /**
     * @deprecated
     */
    protected function loadToken() {
        // Extend this class to re-implement this method
    }

    /**
     * @deprecated
     */
    protected function saveToken() {
        // Extend this class to re-implement this method
    }

}
