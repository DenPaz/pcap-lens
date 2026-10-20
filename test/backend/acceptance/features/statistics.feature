@tshark
Feature: Statistics
  Conversations, endpoints, protocol hierarchy, IO graph, expert info and
  capture properties come from tshark's -z reports (brief 4.6, acceptance criterion 6).

  Background:
    Given the capture "mixed.pcapng" is open

  Scenario: TCP conversations
    When I request the "conversations" statistics for "tcp"
    Then the statistics have 1 row
    And row 1 has "Address A" "192.168.1.10:50000", "Address B" "93.184.216.34:80" and "Packets" 11
    And row 1 filters on "ip.addr == 192.168.1.10 && tcp.port == 50000 && ip.addr == 93.184.216.34 && tcp.port == 80"

  Scenario: UDP conversations
    When I request the "conversations" statistics for "udp"
    Then the statistics have 4 rows

  Scenario: IPv4 endpoints
    When I request the "endpoints" statistics for "ip"
    Then the statistics have 6 rows
    And row 1 has "Address" "192.168.1.10" and "Packets" 19

  Scenario: Protocol hierarchy
    When I request the "phs" statistics
    Then the statistics include "dns" one level below "udp" with 6 packets
    And the statistics include "eth" with 26 packets
    And the top level of the hierarchy covers 26 packets

  Scenario: IO graph with an explicit interval
    When I request the "io" statistics with interval 0.01
    Then the statistics have 5 rows
    And every row has 5 "Packets"

  Scenario: IO graph with several graphs
    When I request the IO graph with interval 0.01 and the graphs "packets of dns", "bits of tcp" and "max of frame.len"
    Then the graph "Packets · dns" adds up to the number of packets matching "dns"
    And the graph "Bits · tcp" is 8 times the bytes matching "tcp" in every interval
    And the graph "MAX(frame.len)" never exceeds the "Bytes" of its interval

  Scenario: An IO graph's bad filter names the graph
    When I request the IO graph with interval 0.01 and the graphs "packets of tcp" and "packets of udp.port =="
    Then the request fails with a filter error for graph 2

  Scenario: Expert information links to packets
    When I request the "expert" statistics
    Then the expert row "Connection finish (FIN)" has severity "Chat", count 2 and frames 18 and 19

  Scenario: Capture file properties
    When I request the "properties" statistics
    Then the property "Number of packets" is "26"

  Scenario: Statistics limited to a display filter
    When I request the "conversations" statistics for "tcp" limited to "http"
    Then row 1 has "Packets" 2

  Scenario: An invalid statistics filter is rejected
    When I request the "conversations" statistics for "tcp" limited to "http =="
    Then the filter is rejected with an error
