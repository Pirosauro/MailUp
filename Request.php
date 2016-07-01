<?php

namespace MailUp;

/**
 * @author  Filippo "Pirosauro" Bovo
 * @package MailUp API client
 * @version 0.1.0
 * @license Apache 2.0
 */

class Request {

    private $options     =  [];

    /**
     * Constructor
     */
    public function __construct() {
    }

    /**
     * Return the list of options
     *
     * @return  array
     */
    public function getOptions() {
        return $this->options;
    }

    /**
     * Set an option
     *
     * @param   string  $key        option name
     * @param   mixed   $value      option value
     * @return  self
     */
    public function setOption($key, $value) {
        $this->options[$key]     =  $value;

        return $this;
    }

    /**
     * Execute the request
     *
     * @return  Response
     */
    public function execute() {
        $curl    =  curl_init();

        foreach ($this->options as $key => $value) {
            curl_setopt($curl, $key, $value);
        }

        //
        curl_setopt($curl, CURLOPT_HEADER, TRUE);

        $result          =  curl_exec($curl);
        $header_size     =  curl_getinfo($curl, CURLINFO_HEADER_SIZE);
        $headers         =  substr($result, 0, $header_size);
        $body            =  substr($result, $header_size);
        $code            =  curl_getinfo($curl, CURLINFO_HTTP_CODE);

        curl_close($curl);

        return (new Response($headers, $body, $code));
    }

}
