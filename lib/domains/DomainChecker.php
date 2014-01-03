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
            // _debug('domain-checker', 'validate ' . $host);
            $this->check($this->get($host));
        }

        return true;
    }

    public function setHost($host) {
        if (false == isset($this->hosts[$host])) {
            $this->hosts[$host] = array();
        }

        $this->host = $host;

        // _debug('domain-checker', 'setHost ' . $host);
    }

    public function get($host) {
        if (false == $this->load($host)) {
            // _debug('domain-checker', 'could not load ' . $host);
            return false;
        }

        return $this->hosts[$host];
    }

    public function load($host) {
        $key = 'domain-check-' . $host;

        if (apc_exists($key)) {
            $this->hosts[$host] = apc_fetch($key);
            // _debug('domain-checker', 'Loading from apc: ' . $host);
            return true;
        }

        $this->hosts[$host] = dns_get_record($host);

        apc_store($key, $this->hosts[$host]);

        // _debug('domain-checker', 'loaded ' . $host);

        return true;
    }

    public function check(array $dnsRecords) {
        $records = $this->mapRecords($dnsRecords);

        // print_r($recordTypes);

        // Look for overall conflicts
        if (array_search('A', $records) && count($records) > 1) {
            throw new DomainCheckerException('Too many A records', 1);
        }

        if (array_search('CNAME', $records) && count($records) > 0 && $this->isRootHost()) {
            throw new DomainCheckerException('CNAME on root domain', 2);
        }

        foreach ($records as $record => $type) {
            // Is an A record but not pointed to Virb
            if ($type == 'A' && $target != '64.207.128.132') {
                throw new DomainCheckerException('A record not pointing to Virb (' . $target . ')', 3);
            }
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
                    // $this->records[$record['host']][] = $record;
                    unset($dnsRecords[$type]);
                    break;
            }
        }

        return $this->records;
    }
}
