<?php

namespace rockerboo\domains\DomainChecker;

class DomainChecker {
    private $hosts = array();
    private $host  = '';

    private $records = array();

    public function __construct($host) {
        $this->setHost($host);
    }

    public function validate() {
        foreach (array_keys($this->hosts) as $host) {
            $this->check($this->get($host));
        }

        return true;
    }

    public function setHost($host) {
        if (false == isset($this->hosts[$host])) {
            $this->hosts[$host] = array();
        }

        $this->host = $host;
    }

    public function get($host) {
        if (false == $this->load($host)) {
            return false;
        }

        return $this->hosts[$host];
    }

    public function load($host) {
        $key = 'domain-check-' . $host;

        if (apc_exists($key)) {
            $this->hosts[$host] = apc_fetch($key);
            return true;
        }

        $this->hosts[$host] = dns_get_record($host);

        apc_store($key, $this->hosts[$host]);

        return true;
    }

    public function check(array $dnsRecords) {
        $records = $this->mapRecords($dnsRecords);
        // Look for overall conflicts
        if (array_search('A', $records) && count($records) > 1) {
            throw new DomainCheckerException('Too many A records', 1);
        }

        if (array_search('CNAME', $records) && count($records) > 0 && $this->isRootHost()) {
            throw new DomainCheckerException('CNAME on root domain', 2);
        }

        return true;
    }

    public function getRecords() {
        return $this->records;
    }

    // FIXME Needs to actually work
    private function isRootHost() {
        return $this->host == 'x' ? true : false;
    }

    private function mapRecords(array $dnsRecords) {
        foreach ($dnsRecords as $type => $record) {
            print_r($record);

            switch ($type) {
                case 'A':
                    $this->records[$record['host']][$record['ip']] = 'A';
                    break;

                case 'CNAME':
                    $this->records[$record['host']][$record['target']] = 'CNAME';
                    break;

                default:
                    unset($dnsRecords[$type]);
                    break;
            }
        }

        return $this->records;
    }
}
