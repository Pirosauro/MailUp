<?php

namespace MailUp;

/**
 * @author  Filippo "Pirosauro" Bovo
 * @package MailUp API client
 * @version 0.1.0
 * @license Apache 2.0
 */

class Response {

    private $raw;
    private $status;

    private $body        =  '';
    private $headers     =  [];

    /**
     * Constructor
     *
     * @param   string  $headers    headers of the response
     * @param   string  $body       body of the response
     * @param   int     $status     HTTP status code
     */
    public function __construct($headers, $body, $status) {
        $this->raw       =  $headers . $body;
        $this->body      =  $body;
        $this->status    =  (int) $status;

        //
        if (strpos($headers, "HTTP/1.1 100 Continue") === 0) {
            $headers     =  str_replace("HTTP/1.1 100 Continue\r\n\r\n", "", $headers);
        }

        if ($headers_array = explode("\r\n", str_replace("\r\n\r\n", '', $headers))) {
            # Extract the version and status from the first header
            if (preg_match('#HTTP/(\d\.\d)\s(\d\d\d)\s(.*)#', array_shift($headers_array), $matches)) {
                $this->headers['Http-Version']   =  $matches[1];
                $this->headers['Status-Code']    =  $matches[2];
                $this->headers['Status']         =  $matches[2] . ' ' . $matches[3];
            }

            # Convert headers into an associative array
            foreach ($headers_array as $header) {
                if (preg_match('#(.*?)\:\s(.*)#', $header, $matches)) {
                    $this->headers[$matches[1]]  =  $matches[2];
                }
            }
        }
    }

    /**
     * Returns the response body
     *
     * @return  string
     */
    public function getBody() {
        return $this->body;
    }

    /**
     * Returns the response headers
     *
     * @return  array
     */
    public function getHeaders() {
        return $this->headers;
    }

    /**
     * Returns a specific response header
     *
     * @param   string  $name
     * @return  mixed
     */
    public function getHeader($name) {
        if (isset($this->headers[$name])) {
            return $this->headers[$name];
        }
    }

    /**
     * Returns the response status code
     *
     * @return  mixed
     */
    public function getStatusCode() {
        return $this->status;
    }

}
