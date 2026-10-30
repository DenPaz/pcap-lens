@tshark
Feature: Session tables
  HTTP requests, DNS queries and TLS servers are shown one row per request,
  query or server instead of per packet: each request with its answer and
  how long it took, and each row filters on exactly its packets.

  Background:
    Given the capture "sessions.pcap" is open

  Scenario: HTTP requests with their responses
    When I request the "http_requests" statistics
    Then the statistics have 5 rows
    And row 1 has "Method" "GET", "Host" "www.example.com", "Path" "/index.html", "Status" 200, "Content Type" "text/html", "Size (bytes)" 15
    And row 1 filters on "frame.number in {4,6}"
    And row 2 has "Path" "/logo.png", "Content Type" "image/png"
    And row 3 has "Method" "POST", "Status" 500, "Reason" "Internal Server Error"
    And row 4 has "Server" "198.51.100.7:8080", "Status" 404

  Scenario: An HTTP request without a response
    When I request the "http_requests" statistics
    Then row 5 has "Path" "/slow", "Reason" "No response"
    And row 5 filters on "frame.number in {26}"

  Scenario: DNS queries with their answers
    When I request the "dns_queries" statistics
    Then the statistics have 5 rows
    And row 1 has "Name" "www.example.com", "Type" "A", "Result" "NoError", "Answers" "A 192.0.2.80, CNAME edge.example.net"
    And row 3 has "Type" "MX", "Answers" "MX mail.example.com"
    And row 4 has "Name" "missing.example.com", "Result" "NXDomain"
    And row 5 has "Name" "lost.example.com", "Result" "No response"

  Scenario: TLS servers by name, with the TLS they chose
    When I request the "tls_servers" statistics
    Then the statistics have 2 rows
    And row 1 has "Server" "198.51.100.20:443", "Server Name (SNI)" "api.example.com", "Connections" 2, "No Server Hello" 0, "Versions" "TLS 1.2, TLS 1.3", "ALPN" "h2"
    And row 1 filters on "tcp.stream in {2..3}"
    And row 2 has "Server Name (SNI)" "cdn.example.net", "Connections" 1, "No Server Hello" 1

  Scenario: Session tables limited to a display filter
    When I request the "http_requests" statistics limited to "tcp.port == 8080"
    Then the statistics have 2 rows
    And row 1 has "Path" "/v1/missing"
