<?php

namespace MailUp;

/**
 * @author  Filippo "Pirosauro" Bovo
 * @package MailUp API client
 * @version 0.1.0
 * @license Apache 2.0
 */

class Logger implements \IteratorAggregate {

    protected $format;

    protected $debug     =  [];

    /**
     * Constructor
     *
     * @param   string  $format     log format
     */
    public function __construct($format = '[{{ date }}] {{ level }}: {{ message }} - {{ code }}') {
        $search      =  [
            '#\{\{[\s]*date[\s]*\}\}#i',
            '#\{\{[\s]*level[\s]*\}\}#i',
            '#\{\{[\s]*message[\s]*\}\}#i',
            '#\{\{[\s]*code[\s]*\}\}#i',
        ];
        $replace     =  [
            '%1$s',
            '%2$10s',
            '%3$s',
            '%4$d',
        ];

        $this->format    =  preg_replace($search, $replace, $format);
    }

    /**
     * @see IteratorAggregate::getIterator()
     */
    public function getIterator() {
        return new \ArrayIterator($this->debug);
    }

    /**
     * Append a custom message to log
     *
     * @param   string  $level      message level
     * @param   string  $message    message lo log
     * @param   int     $code       code
     * @return  self
     */
    public function setMessage($level, $message, $code = 0) {
        $this->debug[]   =  sprintf($this->format, date('c'), (string) $level, substr((string) $message, 0, 255), (int) $code);

        return $this;
    }

    /**
     * Append an exception message to log
     *
     * @param   Exception   $exception
     * @return  self
     */
    public function setException(Exception $exception) {
        $this->setMessage('CRITICAL', $exception->getMessage(), $exception->getCode());

        return $this;
    }

    /**
     * Log a request
     *
     * @param   Request $request    HTTP request
     * @param   string  $verb
     * @return  self
     */
    public function setRequest(Request $request, $verb = NULL) {
        $options     =  $request->getOptions();
        $message     =  isset($options[CURLOPT_URL]) ? $options[CURLOPT_URL] : '';

        // Try to guess
        if (!$verb) {
            if (isset($options[CURLOPT_POST]) && $options[CURLOPT_POST]) {
                $verb    =  'POST';
            }
            else if (isset($options[CURLOPT_PUT]) && $options[CURLOPT_PUT]) {
                $verb    =  'PUT';
            }
            else if (isset($options[CURLOPT_CUSTOMREQUEST]) && ($options[CURLOPT_CUSTOMREQUEST] == 'DELETE')) {
                $verb    =  'DELETE';
            }
            else {
                $verb    =  'GET';
            }
        }

        $this->setMessage('DEBUG', trim($verb . ' ' . $message));

        if ($verb == 'POST') {
            $this->setMessage('DEBUG', print_r($options[CURLOPT_POSTFIELDS], TRUE));
        }

        return $this;
    }

    /**
     * Log a response
     *
     * @param   Response    $response   HTTP response
     * @return  self
     */
    public function setResponse($response) {
        $this->setMessage('DEBUG', $response->getBody(), $response->getStatusCode());

        return $this;
    }

}
